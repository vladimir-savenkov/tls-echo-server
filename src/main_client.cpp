#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>
#include <openssl/ssl.h>
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
            ("cert,c", po::value<std::string>(), "trusted CA certificate (default: system trust store)")
            ("insecure", "disable TLS certificate verification for local tests")
            ("timeout-ms", po::value<int>()->default_value(10000), "deadline per network operation, milliseconds")
            ("payload-size", po::value<int>(), "binary payload size, 0..65535 bytes")
            ("duration", po::value<int>()->default_value(0), "run each connection for this many seconds instead of packet count")
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
        const int timeout_ms = vm["timeout-ms"].as<int>();
        const int duration = vm["duration"].as<int>();
        if (timeout_ms <= 0 || duration < 0 ||
            (vm.count("payload-size") && (vm["payload-size"].as<int>() < 0 ||
                                         vm["payload-size"].as<int>() > 65535)) ||
            (vm.count("insecure") && vm.count("cert")) ||
            (duration > 0 && !vm["packets"].defaulted())) {
            std::cerr << "Ошибка аргументов: проверьте таймаут, размер, длительность; "
                         "--cert/--insecure и --duration/--packets несовместимы\n";
            return 1;
        }
        TlsClientOptions client_options;
        client_options.timeout = std::chrono::milliseconds(timeout_ms);
        client_options.run.duration = std::chrono::seconds(duration);
        if (vm.count("payload-size")) {
            client_options.run.payload_size = static_cast<std::size_t>(vm["payload-size"].as<int>());
        }
        std::string log_file = vm["log-file"].as<std::string>();
        std::string log_level_str = vm["log-level"].as<std::string>();

        // --- 2. Настройка Логгера ---
        // Политика overrun_oldest (create_async_nb): при переполнении очереди
        // теряются самые старые сообщения, но сетевые потоки io_context не
        // блокируются на drain очереди — иначе паузы логгера попадали бы
        // в измеряемые задержки соединений на том же потоке. Файл сбрасывается
        // на диск при warn и выше, чтобы терялись в худшем случае debug/info.
        spdlog::init_thread_pool(8192, 1);
        auto logger = spdlog::create_async_nb<spdlog::sinks::basic_file_sink_mt>(
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

        // Сброс файла на диск только при warn и выше: flush на каждое debug-сообщение
        // тормозит фоновый поток логгера, чаще переполняет очередь и вынуждает её
        // терять сообщения; warn+ критичны для диагностики и сбрасываются сразу.
        logger->flush_on(spdlog::level::warn);

        logger->info("Starting {} clients with {} worker threads, {} packets each; target {}:{}",
                     client_count, thread_count, packet_count, host, port);

        // --- 3. Инициализация контекста ---
        boost::asio::io_context io_context;
        // Отдельные trust store исключают конкурентное изменение ленивых
        // X509-кешей системной OpenSSL 3.0 при проверке сертификатов.
        std::vector<std::unique_ptr<boost::asio::ssl::context>> ssl_contexts;
        ssl_contexts.reserve(static_cast<std::size_t>(client_count));
        for (int index = 0; index < client_count; ++index) {
            // Пол TLS 1.2, потолок открыт: negotiate доходит до TLS 1.3 и выше,
            // поддерживаемых OpenSSL. Фиксация только 1.2 (tlsv12_client) отрезала
            // бы 1-RTT handshake TLS 1.3, влияющий на измеряемую задержку
            // DNS + TCP + TLS; пол ниже 1.2 недопустим (RFC 8996).
            auto context = std::make_unique<boost::asio::ssl::context>(
                boost::asio::ssl::context::tls_client);
            SSL_CTX_set_min_proto_version(context->native_handle(), TLS1_2_VERSION);
            if (vm.count("insecure")) {
                context->set_verify_mode(boost::asio::ssl::verify_none);
            } else {
                context->set_verify_mode(boost::asio::ssl::verify_peer);
                if (vm.count("cert")) context->load_verify_file(vm["cert"].as<std::string>());
                else context->set_default_verify_paths();
            }
            ssl_contexts.push_back(std::move(context));
        }
        if (vm.count("insecure")) logger->warn("Проверка TLS-сертификата отключена (--insecure)");

        // Храним клиентов до завершения всех операций, включая отменённые.
        std::vector<std::unique_ptr<TlsClient>> clients;
        clients.reserve(static_cast<std::size_t>(client_count));
        const auto started_at = std::chrono::steady_clock::now();
        for (int index = 0; index < client_count; ++index) {
            clients.push_back(std::make_unique<TlsClient>(
                io_context, *ssl_contexts[static_cast<std::size_t>(index)], host, port, logger, index + 1, client_options));
            clients.back()->start(packet_count);
        }

        // Все соединения используют общий цикл событий и пул потоков.
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
        std::uint64_t bytes_received = 0;
        LatencyStats request_latency, setup_latency;
        for (std::size_t index = 0; index < clients.size(); ++index) {
            const auto& client = clients[index];
            packets_received += client->packets_received();
            bytes_received += client->bytes_received();
            request_latency.merge(client->latency());
            if (client->setup_microseconds() > 0) setup_latency.record(client->setup_microseconds());
            if (client->succeeded()) {
                ++completed_clients;
            } else {
                logger->error("Client {} failed: {}", index + 1, client->failure_reason());
            }
        }

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started_at);
        const auto expected = duration > 0 ? std::string("duration") :
            std::to_string(static_cast<std::uint64_t>(client_count) * packet_count);
        logger->info("Completed clients: {}/{}; packets received: {}/{}; elapsed: {} ms",
                     completed_clients, client_count, packets_received, expected, elapsed.count());
        const double seconds = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - started_at).count();
        logger->info("Производительность: {:.2f} пакетов/с; {:.2f} MiB/с (эхо, полезные данные)",
                     static_cast<double>(packets_received) / seconds,
                     static_cast<double>(bytes_received) / (1024 * 1024) / seconds);
        logger->info("Задержка запросов, мкс (верхние границы): p50={:.2f}, p95={:.2f}, p99={:.2f}",
                     request_latency.percentile(0.50), request_latency.percentile(0.95),
                     request_latency.percentile(0.99));
        logger->info("DNS + TCP + TLS, мкс (верхние границы): p50={:.2f}, p95={:.2f}, p99={:.2f}",
                     setup_latency.percentile(0.50), setup_latency.percentile(0.95),
                     setup_latency.percentile(0.99));
        return completed_clients == client_count ? 0 : 1;

    } catch (const po::error& e) {
        std::cerr << "Argument parsing error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }
}
