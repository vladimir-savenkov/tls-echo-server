#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <string>
#include "protocol.h"
#include "spdlog/spdlog.h"

class TlsClient {
public:
    explicit TlsClient(boost::asio::io_context& io_context,
                      boost::asio::ssl::context& ssl_context,
                      const std::string& host,
                      unsigned short port,
                      std::shared_ptr<spdlog::logger> logger);

    void start();
    void send_packets(int count);
    void read_response();

private:
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
    std::shared_ptr<spdlog::logger> logger_;

    std::string host_;
    unsigned short port_;

    char header_buf_[sizeof(PacketHeader)];
    std::string payload_buf_;

    int packets_sent_ = 0;
    int packets_received_ = 0;
};

