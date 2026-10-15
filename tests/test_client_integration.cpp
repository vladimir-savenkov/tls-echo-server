#include "basic_client.h"

#include <boost/asio.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {
using boost::asio::ip::tcp;

class TcpConnection {
public:
    explicit TcpConnection(tcp::socket socket) : socket_(std::move(socket)) {}

    template <typename Handler>
    void async_write(std::vector<char> bytes, Handler&& handler) {
        auto buffer = std::make_shared<std::vector<char>>(std::move(bytes));
        boost::asio::async_write(socket_, boost::asio::buffer(*buffer),
            [buffer, handler = std::forward<Handler>(handler)](
                const boost::system::error_code& error, std::size_t size) mutable {
                handler(error, size);
            });
    }

    template <typename Handler>
    void async_read_exactly(std::size_t size, Handler&& handler) {
        auto buffer = std::make_shared<std::vector<char>>(size);
        boost::asio::async_read(socket_, boost::asio::buffer(*buffer),
            [buffer, handler = std::forward<Handler>(handler)](
                const boost::system::error_code& error, std::size_t) mutable {
                handler(error, std::move(*buffer));
            });
    }

    void close() {
        boost::system::error_code ignored;
        socket_.shutdown(tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
    }

private:
    tcp::socket socket_;
};

int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void serve_echo(tcp::acceptor& acceptor, int packet_count,
                bool corrupt_first_response, bool fragment_responses) {
    tcp::socket socket(acceptor.get_executor());
    acceptor.accept(socket);

    for (int index = 0; index < packet_count; ++index) {
        std::array<char, sizeof(PacketHeader)> raw_header{};
        boost::asio::read(socket, boost::asio::buffer(raw_header));

        PacketHeader header{};
        std::memcpy(&header, raw_header.data(), sizeof(header));
        std::vector<char> payload(ntohs(header.len));
        boost::asio::read(socket, boost::asio::buffer(payload));

        std::vector<char> response(raw_header.begin(), raw_header.end());
        response.insert(response.end(), payload.begin(), payload.end());
        if (corrupt_first_response && index == 0 && !payload.empty()) {
            response[sizeof(PacketHeader)] ^= 1;
        }

        if (fragment_responses) {
            for (const char& byte : response) {
                boost::asio::write(socket, boost::asio::buffer(&byte, 1));
            }
        } else {
            boost::asio::write(socket, boost::asio::buffer(response));
        }
    }
}

void run_scenario(int packet_count, bool corrupt_response, bool fragmented,
                  ClientError expected_error, bool expected_complete) {
    boost::asio::io_context server_context;
    tcp::acceptor acceptor(server_context, tcp::endpoint(tcp::v4(), 0));
    std::exception_ptr server_error;
    std::thread server_thread([&] {
        try {
            serve_echo(acceptor, packet_count, corrupt_response, fragmented);
        } catch (...) {
            server_error = std::current_exception();
        }
    });

    boost::asio::io_context client_context;
    tcp::socket socket(client_context);
    socket.connect(tcp::endpoint(
        boost::asio::ip::address_v4::loopback(), acceptor.local_endpoint().port()));
    TcpConnection connection(std::move(socket));
    BasicClient<TcpConnection> client(connection);
    client.send_packets(packet_count);
    client_context.run();

    server_thread.join();
    check(server_error == nullptr, "loopback server completes without error");
    check(client.error() == expected_error, "client reports expected integration result");
    check(client.complete() == expected_complete, "client completion state is correct");
    if (expected_complete) {
        check(client.packets_sent() == packet_count, "all integration packets are sent");
        check(client.packets_received() == packet_count, "all integration packets are received");
    }
}

void test_fragmented_multi_packet_echo() {
    run_scenario(3, false, true, ClientError::none, true);
}

void test_corrupted_echo_response() {
    run_scenario(1, true, false, ClientError::invalid_crc, false);
}
}  // namespace

int main() {
    test_fragmented_multi_packet_echo();
    test_corrupted_echo_response();
    if (failures != 0) {
        std::cerr << failures << " integration test(s) failed\n";
        return 1;
    }
    std::cout << "All client integration tests passed\n";
    return 0;
}
