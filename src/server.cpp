#include "server.h"
#include "protocol.h"
#include "log_payload.h"
#include <boost/asio/bind_executor.hpp>
#include <chrono>
#include <iostream>
#include <algorithm>
#include <utility>

// ============================================================================
// TlsServer Implementation
// ============================================================================

TlsServer::TlsServer(boost::asio::io_context& io_context,
                    boost::asio::ssl::context& ssl_context,
                    unsigned short port,
                    std::shared_ptr<spdlog::logger> logger)
    : io_context_(io_context),
      control_strand_(boost::asio::make_strand(io_context)),
      acceptor_(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      ssl_context_(ssl_context),
      logger_(logger),
      drain_timer_(io_context) {

    logger_->info("Server starting on port {}", port);
    do_accept();
}

TlsServer::~TlsServer() {
    if (acceptor_.is_open()) {
        acceptor_.close();
        logger_->debug("Acceptor closed");
    }
}

void TlsServer::run() {
    logger_->info("Event loop started");
    io_context_.run();
}

void TlsServer::stop() {
    boost::asio::dispatch(control_strand_, [this] {
        if (stopping_) return;
        stopping_ = true;
        logger_->info("Stopping server; waiting for {} active session(s)", active_sessions_);

        boost::system::error_code ec;
        acceptor_.close(ec);
        if (ec) logger_->error("Failed to close acceptor: {}", ec.message());

        if (active_sessions_ != 0) {
            drain_timer_.expires_after(std::chrono::seconds(5));
            drain_timer_.async_wait(boost::asio::bind_executor(control_strand_,
                [this](const boost::system::error_code& timer_error) {
                    if (!timer_error) {
                        logger_->warn("Shutdown timeout with {} active session(s)", active_sessions_);
                        io_context_.stop();
                    }
                }));
        }
    });
}

void TlsServer::session_finished() {
    boost::asio::post(control_strand_, [this] {
        --active_sessions_;
        logger_->debug("Session finished; {} active session(s)", active_sessions_);
        if (stopping_ && active_sessions_ == 0) {
            boost::system::error_code ignored;
            drain_timer_.cancel(ignored);
        }
    });
}

void TlsServer::do_accept() {
    logger_->debug("Server accept scheduled");
    acceptor_.async_accept(boost::asio::bind_executor(control_strand_,
        [this](boost::system::error_code ec,
                                  boost::asio::ip::tcp::socket socket) {
        logger_->debug("Server accept callback: status={}", ec ? ec.message() : "ok");
        if (stopping_) return;
        if (!ec) {
            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket(
                std::move(socket), ssl_context_);

            ++active_sessions_;
            auto session = std::make_shared<Session>(
                std::move(ssl_socket), logger_, [this] { session_finished(); });
            session->start();
        } else {
            logger_->error("Accept error: {}", ec.message());
        }

        do_accept();
    }));
}

// ============================================================================
// Session Implementation
// ============================================================================

TlsServer::Session::Session(boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket,
                             std::shared_ptr<spdlog::logger> logger,
                             std::function<void()> on_finished)
    : socket_(std::move(socket)), logger_(std::move(logger)),
      on_finished_(std::move(on_finished)) {}

void TlsServer::Session::finish() {
    if (finished_) return;
    finished_ = true;
    boost::system::error_code ec;
    socket_.lowest_layer().close(ec);
    logger_->debug("Server TCP close: status={}", ec ? ec.message() : "ok");
    on_finished_();
}

void TlsServer::Session::start() {
    logger_->debug("Server handshake scheduled");
    socket_.async_handshake(boost::asio::ssl::stream_base::server,
        [self = shared_from_this()](boost::system::error_code ec) {
            self->logger_->debug("Server handshake callback: status={}",
                                 ec ? ec.message() : "ok");
            if (!ec) {
                self->logger_->info("Client connected and TLS handshake successful");
                self->read_header();
            } else {
                self->logger_->error("Handshake failed: {}", ec.message());
                self->finish();
            }
        });
}

void TlsServer::Session::read_header() {
    logger_->debug("Server header read scheduled: {} bytes", sizeof(PacketHeader));
    boost::asio::async_read(socket_,
        boost::asio::buffer(header_buf_, sizeof(PacketHeader)),
        [self = shared_from_this()](boost::system::error_code ec, std::size_t bytes_read) {
            self->logger_->debug("Server header callback: bytes={}/{}, status={}",
                                 bytes_read, sizeof(PacketHeader),
                                 ec ? ec.message() : "ok");
            if (!ec) {
                PacketHeader hdr;
                std::memcpy(&hdr, self->header_buf_, sizeof(hdr));

                self->current_id_ = ntohl(hdr.id);
                self->expected_len_ = ntohs(hdr.len);
                self->expected_crc_ = ntohl(hdr.crc);

                self->logger_->debug("Server header parsed: id={}, payload_bytes={}, crc={}",
                               self->current_id_, self->expected_len_, self->expected_crc_);

                self->payload_buf_.resize(self->expected_len_);
                self->read_payload(self->expected_len_);
            } else if (ec == boost::asio::error::eof && bytes_read == 0) {
                self->logger_->debug("Client completed TLS session");
                self->shutdown();
            } else {
                self->logger_->error("Read header failed: {}", ec.message());
                self->finish();
            }
        });
}

void TlsServer::Session::shutdown() {
    logger_->debug("Server TLS shutdown scheduled");
    socket_.async_shutdown([self = shared_from_this()](boost::system::error_code ec) {
        self->logger_->debug("Server TLS shutdown callback: status={}",
                             ec ? ec.message() : "ok");
        self->finish();
    });
}

void TlsServer::Session::read_payload(uint16_t len) {
    logger_->debug("Server payload read scheduled: {} bytes", len);
    boost::asio::async_read(socket_,
        boost::asio::buffer(payload_buf_, len),
        [self = shared_from_this()](boost::system::error_code ec, std::size_t length) {
            self->logger_->debug("Server payload callback: bytes={}/{}, status={}",
                                 length, self->expected_len_,
                                 ec ? ec.message() : "ok");
            if (!ec) {
                ++self->packets_received_;
                if (self->logger_->should_log(spdlog::level::debug)) {
                    self->logger_->debug("Server received packet={}, id={}, data=\"{}\"",
                                         self->packets_received_, self->current_id_,
                                         escape_log_payload(self->payload_buf_));
                }
                uint32_t calc_crc = calculate_crc32(self->payload_buf_.data(), length);
                if (calc_crc != self->expected_crc_) {
                    self->logger_->error("CRC Mismatch! Packet corrupted. Expected: {}, Got: {}",
                                   self->expected_crc_, calc_crc);
                    self->finish();
                    return;
                }

                self->logger_->debug("Server payload validated: id={}, bytes={}",
                                     self->current_id_, length);

                Packet response_pkt(self->current_id_, self->payload_buf_);
                self->write_response(response_pkt);
            } else {
                self->logger_->error("Read payload failed: {}", ec.message());
                self->finish();
            }
        });
}

void TlsServer::Session::write_response(const Packet& pkt) {
    auto buffer = std::make_shared<std::vector<char>>(pkt.serialize());
    if (logger_->should_log(spdlog::level::debug)) {
        logger_->debug("Server sending packet={}, id={}, data=\"{}\"",
                       packets_received_, pkt.id(), escape_log_payload(pkt.payload()));
    }
    logger_->debug("Server response write scheduled: id={}, bytes={}",
                   pkt.id(), buffer->size());

    boost::asio::async_write(socket_,
        boost::asio::buffer(*buffer),
        [self = shared_from_this(), buffer](boost::system::error_code ec, std::size_t bytes_written) {
            self->logger_->debug("Server response write callback: bytes={}/{}, status={}",
                                 bytes_written, buffer->size(),
                                 ec ? ec.message() : "ok");
            if (!ec) {
                self->read_header();
            } else {
                self->logger_->error("Write failed: {}", ec.message());
                self->finish();
            }
        });
}
