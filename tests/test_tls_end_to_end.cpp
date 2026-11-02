#include "client.h"
#include "protocol.h"
#include "server.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

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
PemBundle make_self_signed_pem() {
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
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("tls-echo-test"), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, key);
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
        raw.lowest_layer().connect(
            boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), server.port()), ec);
        check(!ec, "raw client connects");
        raw.handshake(boost::asio::ssl::stream_base::client, ec);
        check(!ec, "raw client completes TLS handshake");

        std::vector<char> bytes = Packet(100U, "legitimate payload").serialize();
        bytes.back() ^= 0xFF;  // повреждаем байт полезной нагрузки -> CRC не сойдётся
        boost::asio::write(raw, boost::asio::buffer(bytes), ec);
        check(!ec, "raw client writes the corrupted packet");

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
}  // namespace

int main() {
    test_tls_echo_round_trip();
    test_server_rejects_corrupted_payload();
    test_client_reports_connect_failure();
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All TLS end-to-end tests passed\n";
    return 0;
}
