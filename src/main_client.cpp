#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include "client.h"
#include "spdlog/async.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    try {
        // --- 1. Парсинг аргументов ---
        po::options_description desc("C++ TLS Client");
        desc.add_options()
            ("help", "show help message")
            ("host,h", po::value<std::string>()->required(), "server host (required; e.g., localhost)")
            ("port,p", po::value<unsigned short>()->default_value(8443), "server port")
            ("clients", po::value<int>()->default_value(1), "number of concurrent connections (positive)")
            ("packets,n", po::value<int>()->default_value(5), "number of packets to send (positive)")
            ("cert,c", po::value<std::string>(), "path to CA cert (optional for self-signed)")
            ("threads,t", po::value<int>()->default_value(1), "number of I/O worker threads (positive)")
            ("log-file,l", po::value<std::string>()->default_value("client.log"), "log file path")
            ("log-level", po::value<std::string>()->default_value("info"), "log level");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return 0;
        }

        po::notify(vm);

        std::string host = vm["host"].as<std::string>();
        unsigned short port = vm["port"].as<unsigned short>();
        int client_count = vm["clients"].as<int>();
        int packet_count = vm["packets"].as<int>();
        int thread_count = vm["threads"].as<int>();
        if (client_count <= 0) {
            std::cerr << "Argument parsing error: --clients must be positive\n";
            return 1;
        }
        if (packet_count <= 0) {
            std::cerr << "Argument parsing error: --packets must be positive\n";
            return 1;
        }
        if (thread_count <= 0) {
            std::cerr << "Argument parsing error: --threads must be positive\n";
            return 1;
        }
        std::string log_file = vm["log-file"].as<std::string>();
        std::string log_level_str = vm["log-level"].as<std::string>();

        // --- 2. Настройка Логгера ---
        spdlog::init_thread_pool(8192, 1);
        auto logger = spdlog::create_async<spdlog::sinks::basic_file_sink_mt>(
            "client", log_file, true);
        auto colored_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        logger->sinks().push_back(colored_sink);
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        if (log_level_str == "trace") logger->set_level(spdlog::level::trace);
        else if (log_level_str == "debug") logger->set_level(spdlog::level::debug);
        else if (log_level_str == "info") logger->set_level(spdlog::level::info);
        else if (log_level_str == "warn") logger->set_level(spdlog::level::warn);
        else if (log_level_str == "error") logger->set_level(spdlog::level::err);
        else if (log_level_str == "critical") logger->set_level(spdlog::level::critical);

        if (logger->level() <= spdlog::level::debug) {
            logger->flush_on(spdlog::level::debug);
        }

        logger->info("Starting {} clients with {} worker threads, {} packets each; target {}:{}",
                     client_count, thread_count, packet_count, host, port);

        // --- 3. Инициализация контекста ---
        boost::asio::io_context io_context;
        boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv12_client);

        // Если передан CA сертификат, используем его для проверки.
        // Если нет - отключаем проверку (для самоподписанных сертификатов в тестах)
        if (vm.count("cert")) {
            std::string ca_path = vm["cert"].as<std::string>();
            ssl_context.load_verify_file(ca_path);
            logger->info("Using CA certificate for verification: {}", ca_path);
        } else {
            ssl_context.set_verify_mode(boost::asio::ssl::verify_none);
            logger->warn("WARNING: Certificate verification disabled (self-signed certs).");
        }

        // Keep every client alive until all asynchronous operations finish.
        std::vector<std::unique_ptr<TlsClient>> clients;
        clients.reserve(static_cast<std::size_t>(client_count));
        const auto started_at = std::chrono::steady_clock::now();
        for (int index = 0; index < client_count; ++index) {
            clients.push_back(std::make_unique<TlsClient>(
                io_context, ssl_context, host, port, logger, index + 1));
            clients.back()->start(packet_count);
        }

        // All connections share one event loop; worker count is independent of client count.
        std::vector<std::thread> workers;
        workers.reserve(static_cast<std::size_t>(thread_count - 1));
        for (int index = 1; index < thread_count; ++index) {
            workers.emplace_back([&io_context]() { io_context.run(); });
        }
        io_context.run();
        for (auto& worker : workers) {
            worker.join();
        }

        int completed_clients = 0;
        std::uint64_t packets_received = 0;
        for (std::size_t index = 0; index < clients.size(); ++index) {
            const auto& client = clients[index];
            packets_received += static_cast<std::uint64_t>(client->packets_received());
            if (client->succeeded()) {
                ++completed_clients;
            } else {
                logger->error("Client {} failed: {}", index + 1, client->failure_reason());
            }
        }

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started_at);
        logger->info("Completed clients: {}/{}; packets received: {}/{}; elapsed: {} ms",
                     completed_clients, client_count, packets_received,
                     static_cast<std::uint64_t>(client_count) * packet_count,
                     elapsed.count());
        return completed_clients == client_count ? 0 : 1;

    } catch (const po::error& e) {
        std::cerr << "Argument parsing error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
