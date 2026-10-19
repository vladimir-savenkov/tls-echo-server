#pragma once

#include <boost/asio.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/strand.hpp>
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
    using Strand = boost::asio::strand<boost::asio::io_context::executor_type>;

    TlsConnection(Stream& socket, Strand& strand,
                  std::shared_ptr<spdlog::logger> logger, int client_number)
        : socket_(socket), strand_(strand), logger_(std::move(logger)),
          client_number_(client_number) {}

    template <typename Handler>
    void async_write(std::vector<char> bytes, Handler&& handler) {
        auto buffer = std::make_shared<std::vector<char>>(std::move(bytes));
        logger_->debug("Client {} write scheduled: {} bytes", client_number_, buffer->size());
        boost::asio::async_write(socket_, boost::asio::buffer(*buffer),
            boost::asio::bind_executor(strand_,
            [this, buffer, handler = std::forward<Handler>(handler)](
                boost::system::error_code error, std::size_t size) mutable {
                logger_->debug("Client {} write callback: bytes={}, status={}",
                               client_number_, size, error ? error.message() : "ok");
                handler(error, size);
            }));
    }

    template <typename Handler>
    void async_read_exactly(std::size_t size, Handler&& handler) {
        auto buffer = std::make_shared<std::vector<char>>(size);
        logger_->debug("Client {} read scheduled: {} bytes", client_number_, size);
        boost::asio::async_read(socket_, boost::asio::buffer(*buffer),
            boost::asio::bind_executor(strand_,
            [this, buffer, handler = std::forward<Handler>(handler)](
                boost::system::error_code error, std::size_t bytes_read) mutable {
                if (!error && bytes_read != buffer->size()) {
                    error = boost::asio::error::message_size;
                }
                logger_->debug("Client {} read callback: bytes={}/{}, status={}",
                               client_number_, bytes_read, buffer->size(),
                               error ? error.message() : "ok");
                handler(error, std::move(*buffer));
            }));
    }

    void close() {
        logger_->debug("Client {} TLS shutdown scheduled", client_number_);
        socket_.async_shutdown(boost::asio::bind_executor(strand_,
            [this](const boost::system::error_code& error) {
            logger_->debug("Client {} TLS shutdown callback: status={}",
                           client_number_, error ? error.message() : "ok");
            boost::system::error_code ignored;
            socket_.lowest_layer().close(ignored);
            logger_->debug("Client {} TCP close: status={}",
                           client_number_, ignored ? ignored.message() : "ok");
        }));
    }

private:
    Stream& socket_;
    Strand& strand_;
    std::shared_ptr<spdlog::logger> logger_;
    int client_number_;
};

class TlsClient {
public:
    explicit TlsClient(boost::asio::io_context& io_context,
                      boost::asio::ssl::context& ssl_context,
                      const std::string& host,
                      unsigned short port,
                      std::shared_ptr<spdlog::logger> logger,
                      int client_number);

    void start(int packet_count);
    bool succeeded() const { return client_.complete(); }
    int packets_received() const { return client_.packets_received(); }
    std::string failure_reason() const;

private:
    void send_packets(int count);

    TlsConnection::Strand strand_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
    TlsConnection connection_;
    BasicClient<TlsConnection> client_;
    std::shared_ptr<spdlog::logger> logger_;

    std::string host_;
    unsigned short port_;
    int client_number_;
    std::string connection_error_;

};
