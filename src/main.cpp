#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>
#include <openssl/ssl.h>
#include <atomic>
#include <csignal>
#include <functional>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <thread>
#include <chrono>
#include "server.h"
#include "logger.h"

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    try {
        // --- 1. Парсинг аргументов ---
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("port,p", po::value<unsigned short>()->default_value(8443), "port to listen on")
            ("bind,b", po::value<std::string>()->default_value("0.0.0.0"),
             "address to listen on: IPv4 or IPv6 (IPv6 enables dual-stack)")
            ("cert,c", po::value<std::string>()->required(), "server certificate path (required)")
            ("key,k", po::value<std::string>()->required(), "server private key path (required)")
            ("threads,t", po::value<int>()->default_value(4), "number of worker threads")
            ("max-connections", po::value<int>()->default_value(1024), "maximum active sessions")
            ("max-payload", po::value<int>()->default_value(65535), "maximum payload, 0..65535 bytes")
            ("timeout-ms", po::value<int>()->default_value(10000), "deadline per network operation, milliseconds")
            ("shutdown-timeout-ms", po::value<int>()->default_value(5000), "active session drain deadline, milliseconds")
            ("log-file,l", po::value<std::string>()->default_value("server.log"), "path to log file")
            ("log-append", "append to the log file instead of truncating it on start")
            ("log-level", po::value<std::string>()->default_value("info"), "log level (trace, debug, info, warn, error, critical)");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return 0;
        }

        po::notify(vm);

        unsigned short port = vm["port"].as<unsigned short>();
        std::string cert_path = vm["cert"].as<std::string>();
        std::string key_path = vm["key"].as<std::string>();
        int thread_count = vm["threads"].as<int>();
        if (thread_count <= 0) {
            std::cerr << "Argument parsing error: --threads must be positive\n";
            return 1;
        }
        const int max_connections = vm["max-connections"].as<int>();
        const int max_payload = vm["max-payload"].as<int>();
        const int timeout_ms = vm["timeout-ms"].as<int>();
        const int shutdown_ms = vm["shutdown-timeout-ms"].as<int>();
        if (max_connections <= 0 || max_payload < 0 || max_payload > 65535 ||
            timeout_ms <= 0 || shutdown_ms <= 0) {
            std::cerr << "Argument parsing error: --max-connections, --max-payload, "
                         "--timeout-ms or --shutdown-timeout-ms is out of range\n";
            return 1;
        }
        ServerOptions server_options;
        server_options.max_connections = static_cast<std::size_t>(max_connections);
        server_options.max_payload = static_cast<std::size_t>(max_payload);
        server_options.operation_timeout = std::chrono::milliseconds(timeout_ms);
        server_options.shutdown_timeout = std::chrono::milliseconds(shutdown_ms);
        boost::system::error_code bind_error;
        server_options.bind_address =
            boost::asio::ip::make_address(vm["bind"].as<std::string>(), bind_error);
        if (bind_error) {
            std::cerr << "Argument parsing error: --bind must be an IPv4 or IPv6 address\n";
            return 1;
        }
        std::string log_file = vm["log-file"].as<std::string>();
        const bool log_append = vm.count("log-append") > 0;
        std::string log_level_str = vm["log-level"].as<std::string>();

        // --- 2. Настройка асинхронного логгера ---
        // Общая политика (очередь overrun_oldest, flush на warn) — в logger.h;
        // --log-append дописывает журнал, без флага файл усекается.
        auto logger = make_logger("server", log_file, log_append);
        logger->set_level(log_level_from_string(log_level_str, *logger));

        logger->info("Logger initialized. Level: {}", log_level_str);

        // --- 3. Инициализация IO Context и SSL ---
        boost::asio::io_context io_context;
        // Пол TLS 1.2, потолок открыт: negotiate доходит до TLS 1.3 и выше,
        // поддерживаемых OpenSSL. Фиксация только 1.2 (tlsv12_server) отрезала
        // бы 1-RTT handshake TLS 1.3, влияющий на измеряемую задержку установки
        // соединения; пол ниже 1.2 недопустим (RFC 8996).
        boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tls_server);
        SSL_CTX_set_min_proto_version(ssl_context.native_handle(), TLS1_2_VERSION);

        ssl_context.use_certificate_file(cert_path, boost::asio::ssl::context::file_format::pem);
        ssl_context.use_private_key_file(key_path, boost::asio::ssl::context::file_format::pem);

        logger->info("SSL Context configured. Cert: {}, Key: {}", cert_path, key_path);

        // --- 4. Создание Сервера ---
        TlsServer server(io_context, ssl_context, port, logger, server_options);
        // Сигналы слушает выделенный io_context в собственном потоке: висящий
        // async_wait не должен держать сетевой io_context, иначе после drain
        // процесс не смог бы завершиться сам. Первый сигнал запускает мягкий
        // drain (до --shutdown-timeout-ms), повторный — force_stop без
        // ожидания. Обработчик реармится в graceful-ветке, чтобы повторный
        // сигнал во время drain был пойман. stop/force_stop диспетчеризуются
        // на control_strand сервера и безопасны из сигнального потока.
        // Счётчик атомарный — страховка на случай добавления потоков к
        // сигнальному io_context; fetch_add различает первый и повторный
        // сигналы, а порядок stop/force на strand безопасен благодаря
        // guard stopping_.
        boost::asio::io_context signal_io;
        boost::asio::signal_set signals(signal_io, SIGINT, SIGTERM);
        const auto signal_count = std::make_shared<std::atomic<int>>(0);
        std::function<void(const boost::system::error_code&, int)> on_signal;
        on_signal = [&server, &signals, signal_count, logger, &on_signal](
                        const boost::system::error_code& error, int signal) {
            if (error) return;
            if (signal_count->fetch_add(1) == 0) {
                logger->info("Received signal {}; starting graceful shutdown", signal);
                server.stop();
            } else {
                logger->warn("Received signal {} again; forcing immediate stop", signal);
                server.force_stop();
                return;  // больше не реармимся: остановка уже принудительная
            }
            signals.async_wait(on_signal);
        };
        signals.async_wait(on_signal);
        std::thread signal_thread([&signal_io] { signal_io.run(); });

        // --- 5. Пул потоков ---
        std::vector<std::thread> threads;
        logger->info("Starting thread pool with {} threads", thread_count);

        for (int i = 0; i < thread_count; ++i) {
            threads.emplace_back([&io_context]() {
                io_context.run();
            });
        }

        // --- 6. Ожидание завершения (Ctrl+C) ---
        logger->info("Server running on port {} with {} threads. Press Ctrl+C to stop.", port, thread_count);

        // Ждем, пока потоки не закончат работу (они будут крутиться в run())
        for (auto& t : threads) {
            t.join();
        }

        // Сетевой io_context опустел — drain завершён. Сигнальный поток
        // держит только async_wait: останавливаем его и ждём.
        signal_io.stop();
        signal_thread.join();

        const auto stats = server.stats();
        logger->info("Server stopped: accepted={}, rejected={}, accept errors={}, "
                     "timed out={}, oversized={}, packets echoed={}, bytes echoed={}, "
                     "active={}", stats.accepted, stats.rejected, stats.accept_errors,
                     stats.timed_out, stats.oversized, stats.packets_echoed,
                     stats.bytes_echoed, stats.active);

    } catch (const po::error& e) {
        std::cerr << "Argument parsing error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
