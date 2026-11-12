#include "client.h"
#include "protocol.h"
#include "server.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <atomic>
#include <array>

#include <spdlog/sinks/null_sink.h>
#include <spdlog/spdlog.h>

#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#include <dirent.h>
#include <sys/resource.h>
#endif

namespace {
int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

// Debug-level logger with a null sink: exercises the debug logging paths of
// TlsServer/TlsClient/BasicClient without cluttering the test output.
std::shared_ptr<spdlog::logger> make_quiet_debug_logger() {
    auto logger = std::make_shared<spdlog::logger>(
        "e2e", std::make_shared<spdlog::sinks::null_sink_mt>());
    logger->set_level(spdlog::level::debug);
    return logger;
}

// Состояние TlsClient/BasicClient не потокобезопасно: все обработчики
// выполняются на вызывающем потоке через io.poll(), и их поля читаются
// только в паузах между обработчиками — без конкурентного доступа.
bool wait_for(boost::asio::io_context& io, const std::function<bool()>& condition,
              std::chrono::seconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!condition()) {
        if (std::chrono::steady_clock::now() > deadline) {
            return false;
        }
        io.poll();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return true;
}

void stop_and_drain(boost::asio::io_context& io, TlsServer& server) {
    boost::asio::post(io, [&server] { server.stop(); });
    while (io.poll() != 0) {
    }
}

struct PemBundle {
    std::string certificate;
    std::string private_key;
};

// Self-signed certificate generated in memory so the test needs no files
// and cannot collide with developer certificates in the working tree.
PemBundle make_self_signed_pem(bool expired = false,
                               const char* names = "DNS:localhost,IP:127.0.0.1") {
    PemBundle bundle;
    EVP_PKEY* key = EVP_RSA_gen(2048);
    X509* cert = X509_new();
    if (key == nullptr || cert == nullptr) {
        check(false, "crypto objects allocate");
        EVP_PKEY_free(key);
        X509_free(cert);
        return bundle;
    }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert), expired ? -60 : 3600);
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("tls-echo-test"), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, key);
    X509_EXTENSION* san = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
        const_cast<char*>(names));
    check(san != nullptr, "certificate SAN is created");
    if (san) {
        X509_add_ext(cert, san, -1);
        X509_EXTENSION_free(san);
    }
    check(X509_sign(cert, key, EVP_sha256()) > 0,
          "self-signed certificate is created");

    BIO* cert_bio = BIO_new(BIO_s_mem());
    BIO* key_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(cert_bio, cert);
    PEM_write_bio_PrivateKey(key_bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(cert_bio, &memory);
    bundle.certificate.assign(memory->data, memory->length);
    BIO_get_mem_ptr(key_bio, &memory);
    bundle.private_key.assign(memory->data, memory->length);
    BIO_free(cert_bio);
    BIO_free(key_bio);
    X509_free(cert);
    EVP_PKEY_free(key);
    return bundle;
}

boost::asio::ssl::context make_server_context(const PemBundle& pem) {
    boost::asio::ssl::context context(boost::asio::ssl::context::tls_server);
    context.use_certificate(boost::asio::buffer(pem.certificate),
                            boost::asio::ssl::context::pem);
    context.use_private_key(boost::asio::buffer(pem.private_key),
                            boost::asio::ssl::context::pem);
    return context;
}

boost::asio::ssl::context make_client_context() {
    boost::asio::ssl::context context(boost::asio::ssl::context::tls_client);
    // Сертификат тестовый и самоподписанный, поэтому проверка цепочки отключена
    context.set_verify_mode(boost::asio::ssl::verify_none);
    return context;
}

void test_tls_echo_round_trip() {
    const PemBundle pem = make_self_signed_pem();
    auto logger = make_quiet_debug_logger();

    boost::asio::io_context io;
    boost::asio::ssl::context server_ctx = make_server_context(pem);
    boost::asio::ssl::context client_ctx = make_client_context();

    TlsServer server(io, server_ctx, 0, logger);  // порт 0 — эфемерный, без коллизий
    check(server.port() != 0, "server reports its bound port");

    TlsClient client(io, client_ctx, "127.0.0.1", server.port(), logger, 1);
    client.start(3);

    const bool finished = wait_for(io, [&client] {
        return client.succeeded() || client.failure_reason() != "none";
    }, std::chrono::seconds(10));
    stop_and_drain(io, server);

    check(finished && client.succeeded(),
          "TLS client completes the request/response sequence in time");
    check(client.packets_received() == 3, "client receives every echoed packet");
    check(client.failure_reason() == "none", "round trip reports no error");

    // Перекрёстная сверка счётчиков: сервер обязан посчитать те же пакеты
    // и те же полезные байты, что получил клиент.
    const auto stats = server.stats();
    check(stats.packets_echoed == client.packets_received(),
          "server counts every echoed packet");
    check(stats.bytes_echoed == client.bytes_received(),
          "server counts echoed payload bytes");
}

void test_server_rejects_corrupted_payload() {
    const PemBundle pem = make_self_signed_pem();
    auto logger = make_quiet_debug_logger();

    boost::asio::io_context io;
    boost::asio::ssl::context server_ctx = make_server_context(pem);
    boost::asio::ssl::context client_ctx = make_client_context();

    TlsServer server(io, server_ctx, 0, logger);

    // Сервер работает в фоне; raw-клиент ниже использует только блокирующие
    // операции и не обращается к состоянию сессий сервера.
    std::thread io_thread([&io] { io.run(); });
    {
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> raw(io, client_ctx);
        boost::system::error_code ec;
        // Wildcard 0.0.0.0 подходит для bind, но Winsock отвергает его в connect.
        raw.lowest_layer().connect(
            boost::asio::ip::tcp::endpoint(
                boost::asio::ip::address_v4::loopback(), server.port()), ec);
        check(!ec, ("raw client connects: " + ec.message()).c_str());
        raw.handshake(boost::asio::ssl::stream_base::client, ec);
        check(!ec, ("raw client completes TLS handshake: " + ec.message()).c_str());

        std::vector<char> bytes = Packet(100U, "legitimate payload").serialize();
        bytes.back() ^= 0xFF;  // повреждаем байт полезной нагрузки -> CRC не сойдётся
        boost::asio::write(raw, boost::asio::buffer(bytes), ec);
        check(!ec, ("raw client writes the corrupted packet: " + ec.message()).c_str());

        char sink[32] = {};
        raw.read_some(boost::asio::buffer(sink), ec);
        check(ec.failed(),
              "server closes the connection instead of echoing a corrupted payload");
        raw.lowest_layer().close(ec);
    }

    boost::asio::post(io, [&server] { server.stop(); });
    io_thread.join();
}

void test_client_reports_connect_failure() {
    const PemBundle pem = make_self_signed_pem();
    auto logger = make_quiet_debug_logger();

    boost::asio::io_context io;
    boost::asio::ssl::context client_ctx = make_client_context();

    // Резервируем эфемерный порт и сразу освобождаем его — там никто не слушает
    unsigned short free_port = 0;
    {
        boost::asio::ip::tcp::acceptor probe(
            io, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
        free_port = probe.local_endpoint().port();
    }

    TlsClient client(io, client_ctx, "127.0.0.1", free_port, logger, 1);
    client.start(1);

    const bool reported = wait_for(io, [&client] {
        return !client.failure_reason().empty() && client.failure_reason() != "none";
    }, std::chrono::seconds(10));

    check(reported, "client reports a failure for a closed port");
    check(client.failure_reason().rfind("connect:", 0) == 0,
          "failure reason names the connect stage");
}
// Проверки TLS identity: все сценарии используют тот же реальный сервер.
void test_certificate_verification() {
    for (int scenario = 0; scenario < 5; ++scenario) {
        const auto pem = make_self_signed_pem(scenario == 3,
            scenario == 2 ? "DNS:wrong.example" : "DNS:localhost,IP:127.0.0.1");
        auto logger = make_quiet_debug_logger();
        boost::asio::io_context io;
        auto server_ctx = make_server_context(pem);
        boost::asio::ssl::context client_ctx(boost::asio::ssl::context::tls_client);
        client_ctx.set_verify_mode(boost::asio::ssl::verify_peer);
        if (scenario != 1) {
            client_ctx.add_certificate_authority(boost::asio::buffer(pem.certificate));
        }
        TlsServer server(io, server_ctx, 0, logger);
        int completions = 0;
        TlsClient client(io, client_ctx, scenario == 4 ? "localhost" : "127.0.0.1",
                         server.port(), logger, 1, {}, [&] { ++completions; });
        client.start(1);
        check(wait_for(io, [&] { return client.finished(); }, std::chrono::seconds(5)),
              "certificate scenario finishes");
        check(client.succeeded() == (scenario == 0 || scenario == 4),
              "trusted DNS/IP succeed; unknown issuer, wrong name and expired identity fail");
        stop_and_drain(io, server);
        check(completions == 1, "certificate outcome completes once");
    }
}

void test_server_deadlines_and_limits() {
    const auto pem = make_self_signed_pem();
    auto logger = make_quiet_debug_logger();
    for (int scenario = 0; scenario < 5; ++scenario) {
        boost::asio::io_context io;
        auto server_ctx = make_server_context(pem);
        auto client_ctx = make_client_context();
        ServerOptions options;
        options.operation_timeout = std::chrono::milliseconds(150);
        options.shutdown_timeout = std::chrono::milliseconds(50);
        options.max_connections = 1;
        options.max_payload = 8;
        TlsServer server(io, server_ctx, 0, logger, options);
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> raw(io, client_ctx);
        raw.next_layer().connect({boost::asio::ip::address_v4::loopback(), server.port()});
        if (scenario == 0 || scenario == 4) {
            // Первый узел не начинает TLS; второй проверяет лимит соединений.
            boost::asio::ip::tcp::socket extra(io);
            if (scenario == 0) extra.connect({boost::asio::ip::address_v4::loopback(), server.port()});
            check(wait_for(io, [&] { return server.stats().active == 1; }, std::chrono::seconds(5)),
                  "server tracks accepted session");
            if (scenario == 4) server.stop();
            check(wait_for(io, [&] { return server.stats().active == 0; }, std::chrono::seconds(5)),
                  "stalled handshake or drain deadline closes the session");
            check(server.stats().timed_out == (scenario == 0 ? 1U : 0U),
                  "operation timeout counted separately from drain cancellation");
            if (scenario == 0) check(server.stats().rejected == 1, "connection limit rejects second peer");
        } else {
            bool handshake_done = false;
            raw.async_handshake(boost::asio::ssl::stream_base::client,
                [&](boost::system::error_code error) {
                    check(!error, "raw client handshake succeeds");
                    handshake_done = true;
                });
            check(wait_for(io, [&] { return handshake_done; }, std::chrono::seconds(5)),
                  "raw client finishes handshake");
            if (scenario == 2 || scenario == 3) {
                auto bytes = Packet(100, scenario == 2 ? "body" : "oversized").serialize();
                // Передаём только заголовок: сервер ждёт payload или отвергает длину.
                boost::asio::write(raw, boost::asio::buffer(bytes.data(), sizeof(PacketHeader)));
            }
            check(wait_for(io, [&] { return server.stats().active == 0; }, std::chrono::seconds(5)),
                  "stalled header/payload or oversized payload is closed");
            check(server.stats().oversized == (scenario == 3 ? 1U : 0U), "oversized header counter");
            check(server.stats().timed_out == (scenario == 3 ? 0U : 1U), "stalled read counter");
        }
        boost::system::error_code ignored;
        raw.next_layer().close(ignored);
        server.stop();
        io.run();
        check(server.stats().active == 0, "server drains all sessions");
    }
}

// Управляемый TLS-узел: молчит на handshake, header, payload либо shutdown.
void test_client_deadlines() {
    const auto pem = make_self_signed_pem();
    auto logger = make_quiet_debug_logger();
    for (int scenario = 0; scenario < 4; ++scenario) {
        boost::asio::io_context io;
        auto server_ctx = make_server_context(pem);
        auto client_ctx = make_client_context();
        boost::asio::ip::tcp::acceptor acceptor(io, {boost::asio::ip::tcp::v4(), 0});
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> peer(io, server_ctx);
        std::array<char, sizeof(PacketHeader)> header{};
        std::vector<char> payload;
        std::vector<char> response;
        acceptor.async_accept(peer.next_layer(), [&](boost::system::error_code error) {
            if (error || scenario == 0) return;
            peer.async_handshake(boost::asio::ssl::stream_base::server,
                [&](boost::system::error_code handshake_error) {
                    if (handshake_error || scenario == 1) return;
                    boost::asio::async_read(peer, boost::asio::buffer(header),
                        [&](boost::system::error_code read_error, std::size_t) {
                            if (read_error) return;
                            PacketHeader decoded{};
                            std::memcpy(&decoded, header.data(), sizeof(decoded));
                            payload.resize(wire::from_network16(decoded.len));
                            boost::asio::async_read(peer, boost::asio::buffer(payload),
                                [&](boost::system::error_code payload_error, std::size_t) {
                                    if (payload_error) return;
                                    response.assign(header.begin(), header.end());
                                    if (scenario == 3) response.insert(response.end(), payload.begin(), payload.end());
                                    boost::asio::async_write(peer, boost::asio::buffer(response),
                                        [](boost::system::error_code, std::size_t) {});
                                });
                        });
                });
        });
        TlsClientOptions options;
        options.timeout = std::chrono::milliseconds(150);
        int completions = 0;
        TlsClient client(io, client_ctx, "127.0.0.1", acceptor.local_endpoint().port(),
                         logger, 1, options, [&] { ++completions; });
        client.start(1);
        check(wait_for(io, [&] { return client.finished(); }, std::chrono::seconds(5)),
              "stalled peer cannot prevent client completion");
        check(!client.succeeded() && client.failure_reason().find("timed out") != std::string::npos,
              "client reports operation timeout");
        check(client.exchange_complete() == (scenario == 3),
              "packet exchange success is distinct from shutdown success");
        boost::system::error_code ignored;
        peer.next_layer().close(ignored);
        acceptor.close(ignored);
        io.run();
        check(completions == 1, "timeout and cancelled callbacks complete once");
    }
}

void test_transport_write_deadline() {
    const auto pem = make_self_signed_pem();
    auto logger = make_quiet_debug_logger();
    boost::asio::io_context io;
    auto server_ctx = make_server_context(pem);
    auto client_ctx = make_client_context();
    boost::asio::ip::tcp::acceptor acceptor(io, {boost::asio::ip::tcp::v4(), 0});
    TlsConnection::Stream peer(io, server_ctx), socket(io, client_ctx);
    auto strand = boost::asio::make_strand(io);
    TlsConnection connection(socket, strand, logger, 1, std::chrono::milliseconds(150),
                             [](boost::system::error_code) {});
    acceptor.async_accept(peer.next_layer(), [&](boost::system::error_code error) {
        if (error) return;
        peer.next_layer().set_option(boost::asio::socket_base::receive_buffer_size(1024));
        peer.async_handshake(boost::asio::ssl::stream_base::server,
                             [](boost::system::error_code) {});
    });
    socket.next_layer().connect({boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()});
    socket.next_layer().set_option(boost::asio::socket_base::send_buffer_size(1024));
    int completions = 0;
    boost::system::error_code result;
    socket.async_handshake(boost::asio::ssl::stream_base::client,
        boost::asio::bind_executor(strand, [&](boost::system::error_code error) {
            check(!error, "write deadline peer completes handshake");
            // Узел не читает TLS-данные; объём превышает размеры TCP-буферов.
            connection.async_write(std::vector<char>(8 * 1024 * 1024, 'x'),
                [&](boost::system::error_code write_error, std::size_t) {
                    result = write_error;
                    ++completions;
                });
        }));
    check(wait_for(io, [&] { return completions != 0; }, std::chrono::seconds(5)),
          "backpressured write finishes within deadline");
    check(result == boost::asio::error::timed_out && connection.timeout_stage() == "write",
          "backpressured write reports its timeout stage");
    connection.abort();
    boost::system::error_code ignored;
    peer.next_layer().close(ignored);
    acceptor.close(ignored);
    io.run();
    check(completions == 1, "cancelled write completes once");
}

void test_shutdown_with_busy_and_idle_sessions() {
    const auto pem = make_self_signed_pem();
    auto logger = make_quiet_debug_logger();
    boost::asio::io_context io;
    auto server_ctx = make_server_context(pem);
    auto client_ctx = make_client_context();
    ServerOptions limits;
    limits.shutdown_timeout = std::chrono::milliseconds(1000);
    TlsServer server(io, server_ctx, 0, logger, limits);
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> idle(io, client_ctx);
    idle.next_layer().connect({boost::asio::ip::address_v4::loopback(), server.port()});
    bool idle_ready = false;
    idle.async_handshake(boost::asio::ssl::stream_base::client, [&](boost::system::error_code error) {
        check(!error, "idle TLS peer handshakes");
        idle_ready = true;
    });
    check(wait_for(io, [&] { return idle_ready; }, std::chrono::seconds(5)), "idle session ready");
    int completions = 0;
    TlsClient client(io, client_ctx, "127.0.0.1", server.port(), logger, 1, {}, [&] { ++completions; });
    client.start(10);
    // poll_one останавливает прогон сразу после accept, пока handshake ещё активен.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (server.stats().accepted < 2 && std::chrono::steady_clock::now() < deadline) io.poll_one();
    check(server.stats().accepted == 2, "busy and idle sessions accepted before stop");
    server.stop();
    io.run();
    check(client.succeeded() && completions == 1, "busy session finishes during grace period");
    check(server.stats().active == 0, "idle TLS session is closed by drain deadline");
    boost::system::error_code ignored;
    idle.next_layer().close(ignored);
}

void test_concurrent_tls_and_shutdown() {
    const auto pem = make_self_signed_pem();
    auto logger = make_quiet_debug_logger();
    boost::asio::io_context io;
    auto server_ctx = make_server_context(pem);
    std::vector<std::unique_ptr<boost::asio::ssl::context>> client_contexts;
    TlsServer server(io, server_ctx, 0, logger);
    std::vector<std::unique_ptr<TlsClient>> clients;
    std::atomic<int> completed{0};
    for (int i = 0; i < 16; ++i) {
        TlsClientOptions options;
        options.run.payload_size = i % 2 == 0 ? 0 : 65535;
        auto context = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tls_client);
        context->set_verify_mode(boost::asio::ssl::verify_peer);
        context->add_certificate_authority(boost::asio::buffer(pem.certificate));
        client_contexts.push_back(std::move(context));
        clients.push_back(std::make_unique<TlsClient>(io, *client_contexts.back(), "127.0.0.1", server.port(),
            logger, i, options, [&] { if (++completed == 16) server.stop(); }));
        clients.back()->start(3);
    }
    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i) workers.emplace_back([&] { io.run(); });
    for (auto& worker : workers) worker.join();
    check(completed == 16, "all concurrent clients complete once");
    for (const auto& client : clients) {
        check(client->succeeded() && client->packets_received() == 3,
              "concurrent TLS exchange succeeds for boundary payloads");
    }
    check(server.stats().active == 0 && server.stats().accepted == 16,
          "server drains concurrent sessions");
    // 16 клиентов по 3 пакета; чётные клиенты — пустой payload, нечётные — 65535.
    check(server.stats().packets_echoed == 48,
          "server counts all concurrent echoed packets");
    check(server.stats().bytes_echoed == 8 * 3 * 65535,
          "server counts concurrent echoed bytes for boundary payloads");
}

#if defined(__linux__)
// Backoff в цикле accept: при исчерпании fd (EMFILE) сервер обязан
// повторять accept с паузой, а не крутиться в busy-loop, и продолжать
// работу после освобождения ресурса. Понижаем лимит дескрипторов
// процесса, открываем «сырые» TCP-соединения без TLS — сервер держит
// их дескрипторы в ожидании handshake, и accept падает с EMFILE.
void test_accept_error_backoff() {
    const auto pem = make_self_signed_pem();
    auto logger = make_quiet_debug_logger();
    boost::asio::io_context io;
    auto server_ctx = make_server_context(pem);
    TlsServer server(io, server_ctx, 0, logger);

    // Сколько дескрипторов открыто сейчас; оставляем процессу лишь
    // небольшой запас, чтобы десятки соединений исчерпали таблицу.
    std::size_t used = 0;
    if (DIR* dir = opendir("/proc/self/fd")) {
        while (readdir(dir) != nullptr) ++used;
        closedir(dir);
    }
    rlimit original{};
    bool limited = getrlimit(RLIMIT_NOFILE, &original) == 0;
    if (limited) {
        rlimit lowered{used + 32, original.rlim_max};
        limited = lowered.rlim_cur <= original.rlim_max &&
            setrlimit(RLIMIT_NOFILE, &lowered) == 0;
    }
    if (!limited) {
        check(false, "accept backoff: fd limit can be lowered");
        return;
    }

    std::vector<boost::asio::ip::tcp::socket> holders;
    for (int i = 0; i < 64; ++i) {
        boost::asio::ip::tcp::socket raw(io);
        boost::system::error_code ec;
        raw.connect({boost::asio::ip::address_v4::loopback(), server.port()}, ec);
        if (ec) break;  // свои дескрипторы исчерпаны
        holders.push_back(std::move(raw));
        io.poll();  // сервер занимает дескриптор принятого соединения
        if (server.stats().accept_errors > 0) break;  // accept уже падает
    }
    check(server.stats().accept_errors > 0,
          "accept fails with EMFILE under fd exhaustion");

    holders.clear();      // серверные сессии увидят EOF и освободят fd
    io.poll();
    setrlimit(RLIMIT_NOFILE, &original);  // вернуть лимит процессу

    // После паузы сервер возобновляет accept и снова обрабатывает echo.
    auto client_ctx = std::make_unique<boost::asio::ssl::context>(
        boost::asio::ssl::context::tls_client);
    client_ctx->set_verify_mode(boost::asio::ssl::verify_peer);
    client_ctx->add_certificate_authority(boost::asio::buffer(pem.certificate));
    int completions = 0;
    TlsClient client(io, *client_ctx, "127.0.0.1", server.port(), logger, 1, {},
                     [&] { ++completions; });
    client.start(5);
    check(wait_for(io, [&] { return completions == 1; }, std::chrono::seconds(10)),
          "server accepts again after accept backoff");
    check(client.succeeded() && client.packets_received() == 5,
          "echo works after accept backoff");
}
#endif

}  // namespace

int main() {
    test_tls_echo_round_trip();
    test_server_rejects_corrupted_payload();
    test_client_reports_connect_failure();
    test_certificate_verification();
    test_server_deadlines_and_limits();
    test_client_deadlines();
    test_concurrent_tls_and_shutdown();
    test_shutdown_with_busy_and_idle_sessions();
    test_transport_write_deadline();
#if defined(__linux__)
    test_accept_error_backoff();
#endif
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All TLS end-to-end tests passed\n";
    return 0;
}
