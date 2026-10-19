#include "client.h"

#include <functional>
#include <string>

namespace {
std::function<void(const std::string&)> make_state_logger(
    const std::shared_ptr<spdlog::logger>& logger, int client_number) {
    if (!logger->should_log(spdlog::level::debug)) {
        return {};
    }
    return [logger, client_number](const std::string& state) {
        logger->debug("Client {} state: {}", client_number, state);
    };
}
}  // namespace

TlsClient::TlsClient(boost::asio::io_context& io_context,
                     boost::asio::ssl::context& ssl_context,
                     const std::string& host,
                     unsigned short port,
                     std::shared_ptr<spdlog::logger> logger,
                     int client_number)
    : strand_(boost::asio::make_strand(io_context)),
      resolver_(io_context),
      socket_(io_context, ssl_context),
      connection_(socket_, strand_, logger, client_number),
      client_(connection_, make_state_logger(logger, client_number)),
      logger_(std::move(logger)),
      host_(host),
      port_(port),
      client_number_(client_number) {}

void TlsClient::start(int packet_count) {
    logger_->debug("Client {} resolve scheduled: {}:{}", client_number_, host_, port_);
    resolver_.async_resolve(host_, std::to_string(port_),
        boost::asio::bind_executor(strand_,
        [this, packet_count](const boost::system::error_code& error,
                             boost::asio::ip::tcp::resolver::results_type endpoints) {
            logger_->debug("Client {} resolve callback: status={}",
                           client_number_, error ? error.message() : "ok");
            if (error) {
                connection_error_ = "resolve: " + error.message();
                logger_->error("Client {} {}", client_number_, connection_error_);
                return;
            }

            logger_->debug("Client {} connect scheduled", client_number_);
            boost::asio::async_connect(socket_.lowest_layer(), endpoints,
                boost::asio::bind_executor(strand_,
                [this, packet_count](const boost::system::error_code& connect_error,
                                     const boost::asio::ip::tcp::endpoint& endpoint) {
                    logger_->debug("Client {} connect callback: status={}",
                                   client_number_, connect_error ? connect_error.message() : "ok");
                    if (connect_error) {
                        connection_error_ = "connect: " + connect_error.message();
                        logger_->error("Client {} {}", client_number_, connection_error_);
                        return;
                    }

                    logger_->debug("Client {} connected to {}:{}; TLS handshake scheduled",
                                   client_number_, endpoint.address().to_string(), endpoint.port());
                    socket_.async_handshake(boost::asio::ssl::stream_base::client,
                        boost::asio::bind_executor(strand_,
                        [this, packet_count](const boost::system::error_code& handshake_error) {
                            logger_->debug("Client {} handshake callback: status={}",
                                           client_number_,
                                           handshake_error ? handshake_error.message() : "ok");
                            if (handshake_error) {
                                connection_error_ = "TLS handshake: " + handshake_error.message();
                                logger_->error("Client {} {}", client_number_, connection_error_);
                                return;
                            }
                            send_packets(packet_count);
                        }));
                }));
        }));
}

void TlsClient::send_packets(int count) {
    logger_->debug("Client {} starting request/response sequence for {} packets",
                   client_number_, count);
    client_.send_packets(count);
}

std::string TlsClient::failure_reason() const {
    if (!connection_error_.empty()) {
        return connection_error_;
    }
    return client_error_name(client_.error());
}
