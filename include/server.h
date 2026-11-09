#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include "operation_deadline.h"
#include "protocol.h"
#include "spdlog/spdlog.h"

struct ServerOptions {
    std::size_t max_connections = 1024;
    std::size_t max_payload = 65535;
    std::chrono::milliseconds operation_timeout{10000};
    std::chrono::milliseconds shutdown_timeout{5000};
};

struct ServerStats {
    uint64_t accepted = 0;
    uint64_t rejected = 0;
    uint64_t timed_out = 0;
    uint64_t oversized = 0;
    uint64_t active = 0;
};

// Владелец хранит сервер до обработки всех операций, включая отменённые.
class TlsServer {
public:
    explicit TlsServer(boost::asio::io_context& io_context,
                      boost::asio::ssl::context& ssl_context, unsigned short port,
                      std::shared_ptr<spdlog::logger> logger, ServerOptions options = {});
    ~TlsServer();
    void run();
    void stop();
    unsigned short port() const { return port_; }
    ServerStats stats() const;

private:
    class Session;
    boost::asio::io_context& io_context_;
    boost::asio::strand<boost::asio::io_context::executor_type> control_strand_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context& ssl_context_;
    std::shared_ptr<spdlog::logger> logger_;
    boost::asio::steady_timer drain_timer_;
    ServerOptions options_;
    unsigned short port_;
    std::unordered_map<uint64_t, std::shared_ptr<Session>> sessions_;
    uint64_t next_session_ = 0;
    bool stopping_ = false;
    std::atomic<uint64_t> accepted_{0}, rejected_{0}, timed_out_{0}, oversized_{0}, active_{0};

    void do_accept();
    void session_finished(uint64_t id, bool timed_out, bool oversized);

    class Session : public std::enable_shared_from_this<Session> {
    public:
        Session(boost::asio::io_context& io, boost::asio::ip::tcp::socket socket,
                boost::asio::ssl::context& ssl, std::shared_ptr<spdlog::logger> logger,
                ServerOptions options, uint64_t session_id,
                std::function<void(bool, bool)> on_finished);
        void start();
        void cancel();
    private:
        void arm(const char* stage);
        bool failed(boost::system::error_code error);
        void read_header();
        void read_payload();
        void write_response();
        void shutdown();
        void finish(bool timed_out = false, bool oversized = false);

        boost::asio::strand<boost::asio::io_context::executor_type> strand_;
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
        OperationDeadline deadline_;
        std::shared_ptr<spdlog::logger> logger_;
        ServerOptions options_;
        uint64_t session_id_ = 0;
        std::function<void(bool, bool)> on_finished_;
        // Адрес удалённой стороны фиксируется один раз при создании: позже сокет
        // может закрыться, и endpoint будет недоступен для логов.
        std::string remote_;
        bool finished_ = false;
        char header_buf_[sizeof(PacketHeader)]{};
        std::string payload_buf_;
        uint32_t current_id_ = 0;
        uint16_t expected_len_ = 0;
        uint32_t expected_crc_ = 0;
    };
};
