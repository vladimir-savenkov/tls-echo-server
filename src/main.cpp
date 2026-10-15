#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>
#include <iostream>
#include <fstream>
#include <memory>
#include <vector>
#include <thread>
#include <chrono>
#include "server.h"
#include "spdlog/async.h"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    try {
        // --- 1. Парсинг аргументов ---
        po::options_description desc("Allowed options");
        desc.add_options()
            ("help", "produce help message")
            ("port,p", po::value<unsigned short>()->default_value(8443), "port to listen on")
            ("cert,c", po::value<std::string>()->required(), "path to server.crt")
            ("key,k", po::value<std::string>()->required(), "path to server.key")
            ("threads,t", po::value<int>()->default_value(4), "number of worker threads")
            ("log-file,l", po::value<std::string>()->default_value("server.log"), "path to log file")
            ("log-level", po::value<std::string>()->default_value("info"), "log level (trace, debug, info, warn, error, critical)");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return 0;
        }

        unsigned short port = vm["port"].as<unsigned short>();
        std::string cert_path = vm["cert"].as<std::string>();
        std::string key_path = vm["key"].as<std::string>();
        int thread_count = vm["threads"].as<int>();
        std::string log_file = vm["log-file"].as<std::string>();
        std::string log_level_str = vm["log-level"].as<std::string>();

        // --- 2. Настройка асинхронного логгера ---
        // Очередь на 8192 сообщения обслуживается одним фоновым потоком.
        spdlog::init_thread_pool(8192, 1);
        auto logger = spdlog::create_async<spdlog::sinks::basic_file_sink_mt>(
            "server", log_file, true);

        // Цветной вывод в консоль (для удобства отладки при запуске)
        auto colored_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        logger->sinks().push_back(colored_sink);

        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        // Установка уровня логирования
        if (log_level_str == "trace") logger->set_level(spdlog::level::trace);
        else if (log_level_str == "debug") logger->set_level(spdlog::level::debug);
        else if (log_level_str == "info") logger->set_level(spdlog::level::info);
        else if (log_level_str == "warn") logger->set_level(spdlog::level::warn);
        else if (log_level_str == "error") logger->set_level(spdlog::level::err);
        else if (log_level_str == "critical") logger->set_level(spdlog::level::critical);
        else {
            logger->warn("Unknown log level '{}', using default 'info'", log_level_str);
        }

        logger->info("Logger initialized. Level: {}", log_level_str);

        // --- 3. Инициализация IO Context и SSL ---
        boost::asio::io_context io_context;
        boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv12_server);

        ssl_context.use_certificate_file(cert_path, boost::asio::ssl::context::file_format::pem);
        ssl_context.use_private_key_file(key_path, boost::asio::ssl::context::file_format::pem);

        logger->info("SSL Context configured. Cert: {}, Key: {}", cert_path, key_path);

        // --- 4. Создание Сервера ---
        TlsServer server(io_context, ssl_context, port, logger);

        // --- 5. Пул потоков ---
        std::vector<std::thread> threads;
        logger->info("Starting thread pool with {} threads", thread_count);

        for (int i = 0; i < thread_count; ++i) {
            threads.emplace_back([&io_context]() {
                io_context.run();
            });
        }

        // --- 6. Ожидание завершения (Ctrl+C) ---
        // В реальном демо-сервере здесь был бы обработчик сигналов
        logger->info("Server running on port {} with {} threads. Press Ctrl+C to stop.", port, thread_count);

        // Ждем, пока потоки не закончат работу (они будут крутиться в run())
        for (auto& t : threads) {
            t.join();
        }

        logger->info("Server stopped");

    } catch (const po::error& e) {
        std::cerr << "Argument parsing error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
