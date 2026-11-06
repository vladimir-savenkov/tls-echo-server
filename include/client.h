#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "basic_client.h"
#include "operation_deadline.h"
#include "spdlog/spdlog.h"

class TlsConnection {
public:
    using Stream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
    using Strand = boost::asio::strand<boost::asio::io_context::executor_type>;
    using CloseHandler = std::function<void(boost::system::error_code)>;

    TlsConnection(Stream& socket, Strand& strand,
                  std::shared_ptr<spdlog::logger> logger, int client_number,
                  std::chrono::milliseconds timeout, CloseHandler on_closed)
        : socket_(socket), strand_(strand), logger_(std::move(logger)),
          client_number_(client_number), deadline_(strand), timeout_(timeout),
          on_closed_(std::move(on_closed)) {}

    template <typename Handler>
    void async_write(std::vector<char> bytes, Handler&& handler) {
        auto buffer = std::make_shared<std::vector<char>>(std::move(bytes));
        begin("write");
        boost::asio::async_write(socket_, boost::asio::buffer(*buffer),
            boost::asio::bind_executor(strand_,
            [this, buffer, handler = std::forward<Handler>(handler)](
                boost::system::error_code error, std::size_t size) mutable {
                handler(end(error), size);
            }));
    }

    template <typename Handler>
    void async_read_exactly(std::size_t size, Handler&& handler) {
        auto buffer = std::make_shared<std::vector<char>>(size);
        begin("read");
        boost::asio::async_read(socket_, boost::asio::buffer(*buffer),
            boost::asio::bind_executor(strand_,
            [this, buffer, handler = std::forward<Handler>(handler)](
                boost::system::error_code error, std::size_t bytes_read) mutable {
                if (!error && bytes_read != buffer->size()) error = boost::asio::error::message_size;
                handler(end(error), std::move(*buffer));
            }));
    }

    void close() {
        begin("TLS shutdown");
        socket_.async_shutdown(boost::asio::bind_executor(strand_,
            [this](boost::system::error_code error) {
                error = end(error);
                abort();
                on_closed_(error);
            }));
    }

    // Аварийное закрытие не ждёт TLS close_notify от неисправного узла.
    void abort() {
        deadline_.cancel();
        boost::system::error_code ignored;
        socket_.lowest_layer().close(ignored);
    }
    const std::string& timeout_stage() const { return timeout_stage_; }

private:
    void begin(const char* stage) {
        logger_->debug("Client {} {} scheduled", client_number_, stage);
        deadline_.arm(timeout_, [this, stage] {
            timeout_stage_ = stage;
            boost::system::error_code ignored;
            socket_.lowest_layer().close(ignored);
        });
    }
    boost::system::error_code end(boost::system::error_code error) {
        if (deadline_.expired()) error = boost::asio::error::timed_out;
        deadline_.cancel();
        return error;
    }
    Stream& socket_;
    Strand& strand_;
    std::shared_ptr<spdlog::logger> logger_;
    int client_number_;
    OperationDeadline deadline_;
    std::chrono::milliseconds timeout_;
    CloseHandler on_closed_;
    std::string timeout_stage_;
};

struct TlsClientOptions {
    std::chrono::milliseconds timeout{10000};
    ClientRunOptions run;
};

// Владелец хранит TlsClient до обработки всех отменённых операций.
// Результаты читаются после завершения io.run() либо на strand клиента.
// Для параллельной верификации на OpenSSL 3.0 используйте отдельные context:
// их общий trust store может изменять ленивые X509-кеши при handshake.
class TlsClient {
public:
    using CompletionHandler = std::function<void()>;
    explicit TlsClient(boost::asio::io_context& io_context,
                      boost::asio::ssl::context& ssl_context,
                      const std::string& host, unsigned short port,
                      std::shared_ptr<spdlog::logger> logger, int client_number,
                      TlsClientOptions options = {}, CompletionHandler on_complete = {});

    void start(int packet_count);
    bool finished() const { return finished_; }
    bool succeeded() const { return finished_ && connection_error_.empty() && client_.complete(); }
    bool exchange_complete() const { return client_.complete(); }
    uint64_t packets_received() const { return client_.packets_received(); }
    uint64_t bytes_received() const { return client_.bytes_received(); }
    const LatencyStats& latency() const { return client_.latency(); }
    double setup_microseconds() const { return setup_microseconds_; }
    std::string failure_reason() const;

private:
    void arm(const char* stage);
    bool stage_failed(const char* stage, boost::system::error_code error);
    void finish(std::string error = {});

    TlsConnection::Strand strand_;
    boost::asio::ip::tcp::resolver resolver_;
    TlsConnection::Stream socket_;
    OperationDeadline deadline_;
    TlsConnection connection_;
    BasicClient<TlsConnection> client_;
    std::shared_ptr<spdlog::logger> logger_;
    std::string host_;
    unsigned short port_;
    int client_number_;
    TlsClientOptions options_;
    CompletionHandler on_complete_;
    std::chrono::steady_clock::time_point started_at_;
    double setup_microseconds_ = 0;
    std::string connection_error_;
    bool started_ = false;
    bool finished_ = false;
};
