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
    void stop();

    // Порт, к которому привязан акцептор (полезно при port == 0 — эфемерный порт)
    unsigned short port() const { return acceptor_.local_endpoint().port(); }

private:
    boost::asio::io_context& io_context_;
    boost::asio::strand<boost::asio::io_context::executor_type> control_strand_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context& ssl_context_;
    std::shared_ptr<spdlog::logger> logger_; // Логгер
    boost::asio::steady_timer drain_timer_;
    std::size_t active_sessions_ = 0;
    bool stopping_ = false;

    void do_accept();
    void session_finished();

    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket,
                std::shared_ptr<spdlog::logger> logger,
                std::function<void()> on_finished);

        void start();
        void read_header();
        void read_payload(uint16_t len);
        void write_response(const Packet& pkt);
        void shutdown();
        void finish();

    private:
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
        std::shared_ptr<spdlog::logger> logger_;
        std::function<void()> on_finished_;
        bool finished_ = false;

        char header_buf_[sizeof(PacketHeader)];
        std::string payload_buf_;

        uint32_t current_id_ = 0;
        uint16_t expected_len_ = 0;
        uint32_t expected_crc_ = 0;
        std::size_t packets_received_ = 0;
    };
};
