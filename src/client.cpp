#include "client.h"

#include <string>

TlsClient::TlsClient(boost::asio::io_context& io_context,
                     boost::asio::ssl::context& ssl_context,
                     const std::string& host,
                     unsigned short port,
                     std::shared_ptr<spdlog::logger> logger)
    : socket_(io_context, ssl_context),
      connection_(socket_),
      client_(connection_),
      logger_(std::move(logger)),
      host_(host),
      port_(port) {}

void TlsClient::start() {
    logger_->info("Connecting to {}:{}...", host_, port_);

    boost::asio::ip::tcp::resolver resolver(socket_.get_executor());
    const auto endpoints = resolver.resolve(host_, std::to_string(port_));
    boost::asio::connect(socket_.lowest_layer(), endpoints);

    logger_->info("Connected. Starting TLS handshake...");
    socket_.async_handshake(boost::asio::ssl::stream_base::client,
        [this](boost::system::error_code error) {
            if (error) {
                logger_->error("TLS Handshake failed: {}", error.message());
                return;
            }
            logger_->info("TLS Handshake successful");
            send_packets(5);
        });
}

void TlsClient::send_packets(int count) {
    logger_->trace("Starting request/response sequence for {} packets", count);
    client_.send_packets(count);
}
