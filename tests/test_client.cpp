#include "basic_client.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include <chrono>
#include <thread>

namespace {
using ErrorCode = boost::system::error_code;

class FakeConnection {
public:
    using WriteHandler = std::function<void(const ErrorCode&, std::size_t)>;
    using ReadHandler = std::function<void(const ErrorCode&, std::vector<char>)>;

    template <typename Handler>
    void async_write(std::vector<char> bytes, Handler&& handler) {
        writes.push_back(std::move(bytes));
        write_handler = std::forward<Handler>(handler);
    }

    template <typename Handler>
    void async_read_exactly(std::size_t size, Handler&& handler) {
        requested_reads.push_back(size);
        read_handler = std::forward<Handler>(handler);
    }

    void abort() { close(); }

    void close() { closed = true; }

    void complete_write(ErrorCode error = {}) {
        auto handler = std::move(write_handler);
        write_handler = {};
        handler(error, writes.back().size());
    }

    void complete_read(std::vector<char> bytes, ErrorCode error = {}) {
        auto handler = std::move(read_handler);
        read_handler = {};
        handler(error, std::move(bytes));
    }

    std::vector<std::vector<char>> writes;
    std::vector<std::size_t> requested_reads;
    WriteHandler write_handler;
    ReadHandler read_handler;
    bool closed = false;
};

int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

ErrorCode test_error() {
    return boost::system::errc::make_error_code(boost::system::errc::io_error);
}

std::vector<char> header_of(const Packet& packet) {
    auto bytes = packet.serialize();
    bytes.resize(sizeof(PacketHeader));
    return bytes;
}

std::vector<char> payload_of(const Packet& packet) {
    const auto bytes = packet.serialize();
    return {bytes.begin() + sizeof(PacketHeader), bytes.end()};
}

uint32_t serialized_id(const std::vector<char>& bytes) {
    PacketHeader header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    return wire::from_network32(header.id);
}

void deliver_response(FakeConnection& connection, const Packet& packet) {
    connection.complete_read(header_of(packet));
    connection.complete_read(payload_of(packet));
}

void test_sequential_request_response_flow() {
    FakeConnection connection;
    BasicClient<FakeConnection> client(connection);
    client.send_packets(2);

    check(connection.writes.size() == 1, "first packet is written immediately");
    check(serialized_id(connection.writes[0]) == 100U, "first packet has id 100");
    check(connection.requested_reads.empty(), "client waits for write completion before reading");

    connection.complete_write();
    check(client.packets_sent() == 1, "successful write increments sent count");
    check(connection.requested_reads == std::vector<std::size_t>{sizeof(PacketHeader)},
          "client requests an exact header");

    deliver_response(connection, Packet(100U, "Hello from C++ Client, packet #0"));
    check(client.packets_received() == 1, "valid response increments received count");
    check(connection.writes.size() == 2, "second write starts after first response");
    check(serialized_id(connection.writes[1]) == 101U, "second packet has id 101");
    check(!connection.closed, "connection remains open before final response");

    connection.complete_write();
    deliver_response(connection, Packet(101U, "Hello from C++ Client, packet #1"));
    check(client.complete(), "client completes requested sequence");
    check(client.error() == ClientError::none, "successful sequence has no error");
    check(client.packets_sent() == 2 && client.packets_received() == 2,
          "client records final packet counts");
    check(connection.closed, "client closes after final response");
}

void test_transport_failures() {
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write(test_error());
        check(client.error() == ClientError::write_failed, "write error is reported");
        check(connection.requested_reads.empty(), "write error prevents reads");
        check(connection.closed, "write failure aborts connection");
    }
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write();
        connection.complete_read({}, test_error());
        check(client.error() == ClientError::header_read_failed, "header error is reported");
        check(connection.closed, "header failure aborts connection");
    }
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write();
        connection.complete_read(header_of(Packet(100U, "answer")));
        connection.complete_read({}, test_error());
        check(client.error() == ClientError::payload_read_failed, "payload error is reported");
        check(connection.closed, "payload failure aborts connection");
    }
}

void test_invalid_responses() {
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write();
        connection.complete_read(std::vector<char>(sizeof(PacketHeader) - 1));
        check(client.error() == ClientError::invalid_header, "short header is rejected");
    }
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write();
        const Packet response(100U, "answer");
        connection.complete_read(header_of(response));
        connection.complete_read(std::vector<char>{'x'});
        check(client.error() == ClientError::invalid_header, "short payload is rejected");
    }
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write();
        auto header = header_of(Packet(100U, "answer"));
        header[0] = static_cast<char>(header[0] ^ 0xFF);  // ломаем старший байт magic
        connection.complete_read(std::move(header));
        check(client.error() == ClientError::invalid_header,
              "response with invalid protocol magic is rejected");
        check(connection.requested_reads == std::vector<std::size_t>{sizeof(PacketHeader)},
              "invalid magic prevents the payload read");
        check(connection.closed, "protocol mismatch aborts connection");
    }
    {
        // Уведомление об ошибке: код сохраняется, payload не читается.
        FakeConnection connection;
        int completions = 0;
        ClientError result = ClientError::none;
        BasicClient<FakeConnection> client(connection, {}, [&](ClientError error) {
            ++completions;
            result = error;
        });
        client.send_packets(1);
        connection.complete_write();
        connection.complete_read(header_of(Packet::make_error(packet_error_oversize)));
        check(result == ClientError::server_rejected,
              "server rejection is reported as server_rejected");
        check(client.server_error_code() == packet_error_oversize,
              "client keeps the server error code");
        check(completions == 1, "rejection completes exactly once");
        check(connection.requested_reads == std::vector<std::size_t>{sizeof(PacketHeader)},
              "error notification does not read a payload");
        check(connection.closed, "server rejection aborts the connection");
    }
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write();
        connection.complete_read(header_of(Packet::make_error(99U)));
        check(client.error() == ClientError::server_rejected &&
                  client.server_error_code() == 99U,
              "unknown server error codes are preserved");
    }
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write();
        auto header = header_of(Packet::make_error(packet_error_oversize));
        header[9] = static_cast<char>(0x01);  // len = 1 у уведомления — нагрузка запрещена
        connection.complete_read(std::move(header));
        check(client.error() == ClientError::invalid_header,
              "error notification with payload is rejected");
    }
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write();
        const Packet response(100U, "answer");
        auto corrupted = payload_of(response);
        corrupted[0] ^= 1;
        connection.complete_read(header_of(response));
        connection.complete_read(std::move(corrupted));
        check(client.error() == ClientError::invalid_crc, "invalid response CRC is rejected");
        check(client.packets_received() == 0, "invalid response is not counted");
    }
    {
        FakeConnection connection;
        BasicClient<FakeConnection> client(connection);
        client.send_packets(1);
        connection.complete_write();
        deliver_response(connection, Packet(999U, "answer"));
        check(client.error() == ClientError::unexpected_packet_id,
              "response with unexpected id is rejected");
    }
}

void test_exact_payload_and_completion() {
    FakeConnection connection;
    int completions = 0;
    ClientError result = ClientError::none;
    BasicClient<FakeConnection> client(connection, {}, [&](ClientError error) {
        ++completions;
        result = error;
    });
    client.send_packets(1);
    connection.complete_write();
    deliver_response(connection, Packet(100U, "different payload with valid CRC"));
    check(client.error() == ClientError::unexpected_payload, "wrong echo with valid CRC is rejected");
    check(client.packets_received() == 0, "wrong echo is not counted");
    check(connection.closed, "invalid echo aborts connection");
    check(completions == 1 && result == ClientError::unexpected_payload,
          "failure completion is delivered exactly once");
}

void test_binary_payload_boundaries() {
    for (std::size_t size : {std::size_t{0}, std::size_t{65535}}) {
        FakeConnection connection;
        int completions = 0;
        ClientRunOptions options;
        options.payload_size = size;
        BasicClient<FakeConnection> client(connection, {}, [&](ClientError error) {
            ++completions;
            check(error == ClientError::none, "binary echo completes successfully");
        }, options);
        client.send_packets(1);
        const auto& bytes = connection.writes[0];
        const auto packet = Packet::deserialize(bytes.data(), sizeof(PacketHeader),
            std::string(bytes.begin() + sizeof(PacketHeader), bytes.end()));
        check(packet.length() == size, "requested binary payload size is used");
        connection.complete_write();
        deliver_response(connection, packet);
        check(client.complete() && completions == 1, "success completes exactly once");
        check(client.bytes_received() == size && client.latency().count() == 1,
              "successful echo contributes bytes and one latency sample");
    }
}

void test_duration_and_histogram() {
    FakeConnection connection;
    ClientRunOptions options;
    options.duration = std::chrono::milliseconds(1);
    BasicClient<FakeConnection> client(connection, {}, {}, options);
    client.send_packets(0);
    check(!connection.writes.empty(), "duration mode sends even with zero packet target");
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    connection.complete_write();
    deliver_response(connection, Packet(100U, "Hello from C++ Client, packet #0"));
    check(client.complete(), "duration mode finishes after an in-flight request completes");

    LatencyStats a;
    LatencyStats b;
    check(a.percentile(0.5) == 0, "empty histogram has no latency");
    a.record(10);
    b.record(100);
    b.record(1000);
    a.merge(b);
    check(a.count() == 3, "merged histogram keeps sample count");
    check(a.percentile(0.5) >= 100 && a.percentile(0.5) < 110,
          "median is the bucket upper bound within documented precision");
    check(a.percentile(0.99) >= 1000 && a.percentile(0.99) < 1100,
          "tail percentile selects the high sample");
}

void test_empty_and_reentrant_sequences() {
    FakeConnection connection;
    BasicClient<FakeConnection> client(connection);
    client.send_packets(0);
    check(client.complete(), "zero packets completes immediately");
    check(connection.writes.empty(), "zero packets performs no write");

    client.send_packets(1);
    client.send_packets(1);
    check(client.error() == ClientError::already_started, "active sequence cannot be restarted");
    check(connection.writes.size() == 1, "restart does not create an overlapping write");
}

// Окно pipelining в режиме длительности: несколько запросов в полёте без
// ответа, read-цепочка одна и живёт, пока окно не опустеет; истёкший срок
// прекращает отправку, но отправленные запросы дорабатываются до полных ответов.
void test_window_pipelining() {
    FakeConnection connection;
    int completions = 0;
    ClientError result = ClientError::none;
    ClientRunOptions options;
    options.duration = std::chrono::milliseconds(100);
    options.window = 3;
    BasicClient<FakeConnection> client(connection, {}, [&](ClientError error) {
        ++completions;
        result = error;
    }, options);
    client.send_packets(5);  // счётчик в режиме длительности игнорируется

    check(connection.writes.size() == 1, "pipelining starts with a single request");
    check(connection.requested_reads.empty(), "read chain waits for the first completed write");
    connection.complete_write();
    check(connection.writes.size() == 2, "second request is pipelined before any response");
    check(connection.requested_reads == std::vector<std::size_t>{sizeof(PacketHeader)},
          "read chain starts with the first completed write");
    connection.complete_write();
    check(connection.writes.size() == 3, "third request fills the window");
    connection.complete_write();
    check(connection.writes.size() == 3, "window is full: no fourth request without a response");
    check(serialized_id(connection.writes[0]) == 100U &&
          serialized_id(connection.writes[1]) == 101U &&
          serialized_id(connection.writes[2]) == 102U,
          "pipelined requests keep sequential ids");

    deliver_response(connection, Packet(100U, "Hello from C++ Client, packet #0"));
    check(client.packets_received() == 1, "first response is processed in order");
    check(connection.writes.size() == 4, "response frees a window slot for the next request");
    check(serialized_id(connection.writes[3]) == 103U, "next request continues the id sequence");
    connection.complete_write();

    // Истечение срока: новые запросы не отправляются, in-flight дорабатываются.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    deliver_response(connection, Packet(101U, "Hello from C++ Client, packet #1"));
    check(connection.writes.size() == 4, "expired duration stops new requests");
    deliver_response(connection, Packet(102U, "Hello from C++ Client, packet #2"));
    deliver_response(connection, Packet(103U, "Hello from C++ Client, packet #3"));
    check(client.complete(), "sequence completes after in-flight responses drain");
    check(completions == 1 && result == ClientError::none,
          "pipelined sequence completes exactly once without error");
    check(client.packets_sent() == 4 && client.packets_received() == 4,
          "pipelined sequence counts sent and received packets");
    check(client.latency().count() == 4, "every response contributes a latency sample");
    check(connection.closed, "completed sequence closes the connection");
}

// Счётный режим форсирует окно 1: строгий запрос/ответ ради честных задержек.
void test_counting_mode_forces_strict_window() {
    FakeConnection connection;
    ClientRunOptions options;
    options.window = 8;
    BasicClient<FakeConnection> client(connection, {}, {}, options);
    check(client.window() == 1, "counting mode forces a single in-flight request");
    client.send_packets(2);
    check(connection.writes.size() == 1, "counting mode sends one request first");
    connection.complete_write();
    check(connection.writes.size() == 1, "no second request before the first response");
    deliver_response(connection, Packet(100U, "Hello from C++ Client, packet #0"));
    check(connection.writes.size() == 2, "next request waits for the previous response");
    connection.complete_write();
    deliver_response(connection, Packet(101U, "Hello from C++ Client, packet #1"));
    check(client.complete() && client.error() == ClientError::none,
          "strict sequence completes in counting mode");
}

// Окно вне диапазона 1..1024 отвергается конструктором.
void test_window_validation() {
    for (const std::size_t window : {std::size_t{0}, max_client_window + 1}) {
        bool threw = false;
        try {
            FakeConnection connection;
            ClientRunOptions options;
            options.duration = std::chrono::milliseconds(1);
            options.window = window;
            BasicClient<FakeConnection> client(connection, {}, {}, options);
            client.send_packets(0);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        check(threw, "window out of range is rejected by the constructor");
    }
}

// Чужой id внутри окна: порядок ответов FIFO, иначе отказ соединения.
void test_window_rejects_unexpected_id() {
    FakeConnection connection;
    ClientRunOptions options;
    options.duration = std::chrono::milliseconds(100);
    options.window = 3;
    BasicClient<FakeConnection> client(connection, {}, {}, options);
    client.send_packets(5);
    connection.complete_write();
    connection.complete_write();
    connection.complete_write();
    deliver_response(connection, Packet(105U, "Hello from C++ Client, packet #0"));
    check(client.error() == ClientError::unexpected_packet_id,
          "foreign id inside the window is rejected");
    check(connection.closed, "unexpected id aborts the pipelined connection");
}

// Ошибка транспорта посреди окна: abort и единственный completion.
void test_window_transport_failure() {
    {
        FakeConnection connection;
        ClientRunOptions options;
        options.duration = std::chrono::milliseconds(100);
        options.window = 3;
        BasicClient<FakeConnection> client(connection, {}, {}, options);
        client.send_packets(5);
        connection.complete_write();
        connection.complete_write();
        connection.complete_write(test_error());
        check(client.error() == ClientError::write_failed,
              "write error inside the window aborts the sequence");
        check(connection.closed, "write failure aborts the pipelined connection");
    }
    {
        FakeConnection connection;
        int completions = 0;
        ClientRunOptions options;
        options.duration = std::chrono::milliseconds(100);
        options.window = 3;
        BasicClient<FakeConnection> client(connection, {},
            [&](ClientError) { ++completions; }, options);
        client.send_packets(5);
        connection.complete_write();
        connection.complete_write();
        connection.complete_write();
        connection.complete_read({}, test_error());
        check(client.error() == ClientError::header_read_failed,
              "header error inside the window aborts the sequence");
        check(completions == 1, "transport failure completes exactly once");
        check(connection.closed, "read failure aborts the pipelined connection");
    }
}
}  // namespace

// Необработанное исключение обрушивает тест — это и есть сигнал провала.
int main() {  // NOLINT(bugprone-exception-escape)
    test_sequential_request_response_flow();
    test_transport_failures();
    test_invalid_responses();
    test_empty_and_reentrant_sequences();
    test_exact_payload_and_completion();
    test_binary_payload_boundaries();
    test_duration_and_histogram();
    test_window_pipelining();
    test_counting_mode_forces_strict_window();
    test_window_validation();
    test_window_rejects_unexpected_id();
    test_window_transport_failure();
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All BasicClient tests passed\n";
    return 0;
}
