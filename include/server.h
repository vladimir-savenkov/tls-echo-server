#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <string>
#include <functional>
#include "protocol.h"
#include "spdlog/spdlog.h"

class TlsServer {
public:
    // Конструктор теперь принимает логгер
    explicit TlsServer(boost::asio::io_context& io_context, 
                      boost::asio::ssl::context& ssl_context, 
                      unsigned short port,
                      std::shared_ptr<spdlog::logger> logger);

    ~TlsServer();

    void run();

private:
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context& ssl_context_;
    std::shared_ptr<spdlog::logger> logger_; // Логгер

    void do_accept();

    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket,
                std::shared_ptr<spdlog::logger> logger);

        void start();
        void read_header();
        void read_payload(uint16_t len);
        void write_response(const Packet& pkt);

    private:
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
        std::shared_ptr<spdlog::logger> logger_;

        char header_buf_[sizeof(PacketHeader)];
        std::string payload_buf_;

        uint32_t current_id_ = 0;
        uint16_t expected_len_ = 0;
        uint32_t expected_crc_ = 0;
    };
};

