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

    LatencyStats a, b;
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
}  // namespace

int main() {
    test_sequential_request_response_flow();
    test_transport_failures();
    test_invalid_responses();
    test_empty_and_reentrant_sequences();
    test_exact_payload_and_completion();
    test_binary_payload_boundaries();
    test_duration_and_histogram();
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All BasicClient tests passed\n";
    return 0;
}
