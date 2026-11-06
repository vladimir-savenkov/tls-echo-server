#include "server.h"
#include "log_payload.h"
#include <array>
#include <cstring>
#include <stdexcept>
#include <utility>

TlsServer::TlsServer(boost::asio::io_context& io_context,
                    boost::asio::ssl::context& ssl_context, unsigned short port,
                    std::shared_ptr<spdlog::logger> logger, ServerOptions options)
    : io_context_(io_context), control_strand_(boost::asio::make_strand(io_context)),
      acceptor_(io_context), ssl_context_(ssl_context), logger_(std::move(logger)),
      drain_timer_(control_strand_), options_(options), port_(port) {
    if (options_.max_connections == 0 || options_.max_payload > 65535 ||
        options_.operation_timeout.count() <= 0 || options_.shutdown_timeout.count() <= 0) {
        throw std::invalid_argument("Invalid server limits or timeouts");
    }
    acceptor_.open(boost::asio::ip::tcp::v4());
    acceptor_.set_option(boost::asio::socket_base::reuse_address(true));
    acceptor_.bind({boost::asio::ip::tcp::v4(), port});
    acceptor_.listen();
    port_ = acceptor_.local_endpoint().port();
    logger_->info("Server starting on port {}", port_);
    do_accept();
}

TlsServer::~TlsServer() {
    boost::system::error_code ignored;
    acceptor_.close(ignored);
}

void TlsServer::run() { io_context_.run(); }

ServerStats TlsServer::stats() const {
    return {accepted_.load(), rejected_.load(), timed_out_.load(), oversized_.load(), active_.load()};
}

void TlsServer::stop() {
    boost::asio::dispatch(control_strand_, [this] {
        if (stopping_) return;
        stopping_ = true;
        boost::system::error_code ignored;
        acceptor_.close(ignored);
        logger_->info("Stopping server; waiting for {} active session(s)", sessions_.size());
        if (sessions_.empty()) return;
        drain_timer_.expires_after(options_.shutdown_timeout);
        drain_timer_.async_wait([this](boost::system::error_code error) {
            if (error) return;
            logger_->warn("Shutdown deadline: closing {} session(s)", sessions_.size());
            // Закрываем сокеты и обрабатываем отменённые операции до выхода io.run().
            for (const auto& entry : sessions_) entry.second->cancel();
        });
    });
}

void TlsServer::session_finished(uint64_t id, bool timed_out, bool oversized) {
    boost::asio::post(control_strand_, [this, id, timed_out, oversized] {
        sessions_.erase(id);
        active_ = sessions_.size();
        if (timed_out) ++timed_out_;
        if (oversized) ++oversized_;
        if (stopping_ && sessions_.empty()) {
            drain_timer_.cancel();
        }
    });
}

void TlsServer::do_accept() {
    acceptor_.async_accept(boost::asio::bind_executor(control_strand_,
        [this](boost::system::error_code error, boost::asio::ip::tcp::socket socket) {
            if (stopping_) return;
            if (!error) {
                if (sessions_.size() >= options_.max_connections) {
                    ++rejected_;
                    boost::system::error_code ignored;
                    socket.close(ignored);
                } else {
                    const auto id = ++next_session_;
                    auto session = std::make_shared<Session>(io_context_, std::move(socket),
                        ssl_context_, logger_, options_, [this, id](bool timeout, bool oversized) {
                            session_finished(id, timeout, oversized);
                        });
                    sessions_.emplace(id, session);
                    ++accepted_;
                    active_ = sessions_.size();
                    session->start();
                }
            } else {
                logger_->error("Accept error: {}", error.message());
            }
            do_accept();
        }));
}

TlsServer::Session::Session(boost::asio::io_context& io, boost::asio::ip::tcp::socket socket,
                           boost::asio::ssl::context& ssl,
                           std::shared_ptr<spdlog::logger> logger, ServerOptions options,
                           std::function<void(bool, bool)> on_finished)
    : strand_(boost::asio::make_strand(io)), socket_(std::move(socket), ssl),
      deadline_(strand_), logger_(std::move(logger)), options_(options),
      on_finished_(std::move(on_finished)) {
    // TCP_NODELAY: без него алгоритм Нагла придерживает хвостовые сегменты
    // ответов до ACK клиента, и паузы delayed-ACK ядра (до 40 мс на Linux,
    // 200 мс на Windows) попадают в измеряемые задержки echo.
    boost::system::error_code nodelay_error;
    socket_.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(true), nodelay_error);
    if (nodelay_error) {
        logger_->warn("Cannot disable Nagle algorithm: {}", nodelay_error.message());
    } else {
        logger_->debug("TCP_NODELAY enabled on session socket");
    }
}

void TlsServer::Session::arm(const char* stage) {
    logger_->debug("Server {} scheduled", stage);
    deadline_.arm(options_.operation_timeout, [self = shared_from_this(), stage] {
        self->logger_->warn("Server {} timed out", stage);
        self->finish(true);
    });
}

bool TlsServer::Session::failed(boost::system::error_code error) {
    deadline_.cancel();
    if (finished_) return true;
    if (error) {
        logger_->debug("Server operation failed: {}", error.message());
        finish();
        return true;
    }
    return false;
}

void TlsServer::Session::finish(bool timed_out, bool oversized) {
    if (finished_) return;
    finished_ = true;
    deadline_.cancel();
    boost::system::error_code ignored;
    socket_.lowest_layer().close(ignored);
    on_finished_(timed_out, oversized);
}

void TlsServer::Session::cancel() {
    boost::asio::dispatch(strand_, [self = shared_from_this()] { self->finish(); });
}

void TlsServer::Session::start() {
    boost::asio::dispatch(strand_, [self = shared_from_this()] {
        if (self->finished_) return;
        self->arm("TLS handshake");
        self->socket_.async_handshake(boost::asio::ssl::stream_base::server,
            boost::asio::bind_executor(self->strand_,
            [self](boost::system::error_code error) {
                if (!self->failed(error)) self->read_header();
            }));
    });
}

void TlsServer::Session::read_header() {
    arm("header read");
    boost::asio::async_read(socket_, boost::asio::buffer(header_buf_),
        boost::asio::bind_executor(strand_,
        [self = shared_from_this()](boost::system::error_code error, std::size_t size) {
            if (!self->finished_ && error == boost::asio::error::eof && size == 0) {
                self->deadline_.cancel();
                self->shutdown();
                return;
            }
            if (self->failed(error)) return;
            PacketHeader header{};
            std::memcpy(&header, self->header_buf_, sizeof(header));
            self->current_id_ = wire::from_network32(header.id);
            self->expected_len_ = wire::from_network16(header.len);
            self->expected_crc_ = wire::from_network32(header.crc);
            if (self->expected_len_ > self->options_.max_payload) {
                self->logger_->warn("Payload exceeds server limit: {}", self->expected_len_);
                self->finish(false, true);
                return;
            }
            self->payload_buf_.resize(self->expected_len_);
            self->read_payload();
        }));
}

void TlsServer::Session::read_payload() {
    arm("payload read");
    boost::asio::async_read(socket_, boost::asio::buffer(payload_buf_),
        boost::asio::bind_executor(strand_,
        [self = shared_from_this()](boost::system::error_code error, std::size_t size) {
            if (self->failed(error)) return;
            if (calculate_crc32(self->payload_buf_.data(), size) != self->expected_crc_) {
                self->logger_->warn("CRC mismatch: id={}", self->current_id_);
                self->finish();
                return;
            }
            if (self->logger_->should_log(spdlog::level::debug)) {
                self->logger_->debug("Server received id={}, data=\"{}\"", self->current_id_,
                                     escape_log_payload(self->payload_buf_));
            }
            self->write_response();
        }));
}

void TlsServer::Session::write_response() {
    if (logger_->should_log(spdlog::level::debug)) {
        logger_->debug("Server sending id={}, data=\"{}\"", current_id_,
                       escape_log_payload(payload_buf_));
    }
    // Echo-ответ байт-в-байт совпадает с принятыми данными: header_buf_ уже
    // содержит id/len/crc в сетевом порядке, payload_buf_ — данные. Пишем оба
    // буфера одной операцией без промежуточных копий и аллокаций. Asio
    // копирует объект-последовательность внутрь операции, а сами данные —
    // члены Session, чей lifetime держит захват self в обработчике.
    arm("response write");
    const std::array<boost::asio::const_buffer, 2> response_buffers{
        boost::asio::buffer(header_buf_),
        boost::asio::buffer(payload_buf_)};
    boost::asio::async_write(socket_, response_buffers,
        boost::asio::bind_executor(strand_,
        [self = shared_from_this()](boost::system::error_code error, std::size_t) {
            if (!self->failed(error)) self->read_header();
        }));
}

void TlsServer::Session::shutdown() {
    arm("TLS shutdown");
    socket_.async_shutdown(boost::asio::bind_executor(strand_,
        [self = shared_from_this()](boost::system::error_code error) {
            if (!self->failed(error)) self->finish();
        }));
}
