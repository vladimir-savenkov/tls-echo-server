#include "client.h"

#include <openssl/ssl.h>
#include <stdexcept>

namespace {
std::function<void(const std::string&)> make_state_logger(
    const std::shared_ptr<spdlog::logger>& logger, int client_number) {
    if (!logger->should_log(spdlog::level::debug)) return {};
    return [logger, client_number](const std::string& state) {
        logger->debug("Client {} state: {}", client_number, state);
    };
}
}  // namespace

TlsClient::TlsClient(boost::asio::io_context& io_context,
                     boost::asio::ssl::context& ssl_context,
                     std::string host, unsigned short port,
                     std::shared_ptr<spdlog::logger> logger, int client_number,
                     TlsClientOptions options, CompletionHandler on_complete)
    : strand_(boost::asio::make_strand(io_context)), resolver_(io_context),
      socket_(io_context, ssl_context), deadline_(strand_),
      connection_(socket_, strand_, logger, client_number, options.timeout,
          [this](boost::system::error_code error) {
              finish(error ? "TLS shutdown: " + error.message() : "");
          }),
      client_(connection_, make_state_logger(logger, client_number),
          [this](ClientError error) {
              if (error != ClientError::none) finish(client_error_name(error));
          }, options.run),
      logger_(std::move(logger)), host_(std::move(host)), port_(port),
      client_number_(client_number), options_(options), on_complete_(std::move(on_complete)) {
    if (options_.timeout.count() <= 0) throw std::invalid_argument("Timeout must be positive");
    socket_.set_verify_callback(boost::asio::ssl::host_name_verification(host_));
    boost::system::error_code error;
    boost::asio::ip::make_address(host_, error);
    if (error && SSL_set_tlsext_host_name(socket_.native_handle(), host_.c_str()) != 1) {
        throw std::runtime_error("Cannot set TLS server name");
    }
}

void TlsClient::arm(const char* stage) {
    logger_->debug("Client {} {} scheduled", client_number_, stage);
    deadline_.arm(options_.timeout, [this, stage] {
        resolver_.cancel();
        finish(std::string(stage) + ": timed out");
    });
}

bool TlsClient::stage_failed(const char* stage, boost::system::error_code error) {
    deadline_.cancel();
    if (finished_) return true;
    if (error) {
        finish(std::string(stage) + ": " + error.message());
        return true;
    }
    return false;
}

void TlsClient::start(int packet_count) {
    boost::asio::dispatch(strand_, [this, packet_count] {
        if (started_) return;
        started_ = true;
        started_at_ = std::chrono::steady_clock::now();
        arm("resolve");
        resolver_.async_resolve(host_, std::to_string(port_),
            boost::asio::bind_executor(strand_,
            [this, packet_count](boost::system::error_code error,
                                const boost::asio::ip::tcp::resolver::results_type& endpoints) {
                if (stage_failed("resolve", error)) return;
                arm("connect");
                boost::asio::async_connect(socket_.lowest_layer(), endpoints,
                    boost::asio::bind_executor(strand_,
                    [this, packet_count](boost::system::error_code connect_error,
                                         const boost::asio::ip::tcp::endpoint&) {
                        if (stage_failed("connect", connect_error)) return;
                        // TCP_NODELAY до handshake: и записи handshake, и запросы
                        // не должны ждать ACK по алгоритму Нагла — иначе паузы
                        // delayed-ACK ядра попадают в измеряемые задержки.
                        boost::system::error_code nodelay_error;
                        socket_.lowest_layer().set_option(
                            boost::asio::ip::tcp::no_delay(true), nodelay_error);
                        if (nodelay_error) {
                            logger_->warn("Client {}: cannot disable Nagle algorithm: {}",
                                          client_number_, nodelay_error.message());
                        } else {
                            logger_->debug("Client {}: TCP_NODELAY enabled", client_number_);
                        }
                        arm("TLS handshake");
                        socket_.async_handshake(boost::asio::ssl::stream_base::client,
                            boost::asio::bind_executor(strand_,
                            [this, packet_count](boost::system::error_code handshake_error) {
                                if (stage_failed("TLS handshake", handshake_error)) return;
                                setup_microseconds_ = std::chrono::duration<double, std::micro>(
                                    std::chrono::steady_clock::now() - started_at_).count();
                                client_.send_packets(packet_count);
                            }));
                    }));
            }));
    });
}

void TlsClient::finish(std::string error) {
    if (finished_) return;
    finished_ = true;
    deadline_.cancel();
    connection_.abort();
    connection_error_ = std::move(error);
    if (!connection_.timeout_stage().empty()) {
        std::string stage = connection_.timeout_stage();
        if (stage == "read") {
            stage = client_.error() == ClientError::header_read_failed ? "header read" : "payload read";
        }
        connection_error_ = stage + ": timed out";
    }
    if (!connection_error_.empty()) logger_->error("Client {} {}", client_number_, connection_error_);
    if (on_complete_) on_complete_();
}

std::string TlsClient::failure_reason() const {
    return connection_error_.empty() ? client_error_name(client_.error()) : connection_error_;
}
