#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>
#include <iostream>
#include <memory>
#include <string>
#include "client.h"
#include "spdlog/spdlog.h"
#include "spdlog/async_logger.h"

namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    try {
        // --- 1. Парсинг аргументов ---
        po::options_description desc("C++ TLS Client");
        desc.add_options()
            ("help", "show help message")
            ("host,h", po::value<std::string>()->required(), "server host (e.g., localhost)")
            ("port,p", po::value<unsigned short>()->default_value(8443), "server port")
            ("cert,c", po::value<std::string>(), "path to CA cert (optional for self-signed)")
            ("threads,t", po::value<int>()->default_value(1), "number of threads (usually 1 for client)")
            ("log-file,l", po::value<std::string>()->default_value("client.log"), "log file path")
            ("log-level", po::value<std::string>()->default_value("info"), "log level");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << "\n";
            return 0;
        }

        std::string host = vm["host"].as<std::string>();
        unsigned short port = vm["port"].as<unsigned short>();
        std::string log_file = vm["log-file"].as<std::string>();
        std::string log_level_str = vm["log-level"].as<std::string>();

        // --- 2. Настройка Логгера ---
        auto logger = spdlog::create_async<spdlog::sinks::basic_file_sink_mt>(log_file, true, 8192, spdlog::async_overflow_policy::block, 1000);
        auto colored_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        logger->sinks().push_back(colored_sink);
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");

        if (log_level_str == "trace") logger->set_level(spdlog::level::trace);
        else if (log_level_str == "debug") logger->set_level(spdlog::level::debug);
        else if (log_level_str == "info") logger->set_level(spdlog::level::info);
        else if (log_level_str == "warn") logger->set_level(spdlog::level::warn);
        else if (log_level_str == "error") logger->set_level(spdlog::level::err);
        else if (log_level_str == "critical") logger->set_level(spdlog::level::critical);

        logger->info("Client started. Connecting to {}:{}", host, port);

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

        // --- 4. Создание и запуск клиента ---
        TlsClient client(io_context, ssl_context, host, port, logger);
        client.start();

        // --- 5. Запуск цикла событий ---
        // Клиент обычно однопоточный, но используем thread для единообразия
        std::thread t([&io_context]() {
            io_context.run();
        });

        t.join();

        logger->info("Client finished.");

    } catch (const po::error& e) {
        std::cerr << "Argument parsing error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}

