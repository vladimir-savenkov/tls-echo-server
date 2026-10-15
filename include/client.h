#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "basic_client.h"
#include "protocol.h"
#include "spdlog/spdlog.h"

class TlsConnection {
public:
    using Stream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

    explicit TlsConnection(Stream& socket) : socket_(socket) {}

    template <typename Handler>
    void async_write(std::vector<char> bytes, Handler&& handler) {
        auto buffer = std::make_shared<std::vector<char>>(std::move(bytes));
        boost::asio::async_write(socket_, boost::asio::buffer(*buffer),
            [buffer, handler = std::forward<Handler>(handler)](
                boost::system::error_code error, std::size_t size) mutable {
                handler(error, size);
            });
    }

    template <typename Handler>
    void async_read_exactly(std::size_t size, Handler&& handler) {
        auto buffer = std::make_shared<std::vector<char>>(size);
        boost::asio::async_read(socket_, boost::asio::buffer(*buffer),
            [buffer, handler = std::forward<Handler>(handler)](
                boost::system::error_code error, std::size_t bytes_read) mutable {
                if (!error && bytes_read != buffer->size()) {
                    error = boost::asio::error::message_size;
                }
                handler(error, std::move(*buffer));
            });
    }

    void close() { socket_.lowest_layer().close(); }

private:
    Stream& socket_;
};

class TlsClient {
public:
    explicit TlsClient(boost::asio::io_context& io_context,
                      boost::asio::ssl::context& ssl_context,
                      const std::string& host,
                      unsigned short port,
                      std::shared_ptr<spdlog::logger> logger);

    void start();
    void send_packets(int count);

private:
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
    TlsConnection connection_;
    BasicClient<TlsConnection> client_;
    std::shared_ptr<spdlog::logger> logger_;

    std::string host_;
    unsigned short port_;

};
