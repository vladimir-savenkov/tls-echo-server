#pragma once

#include "protocol.h"

#include <boost/system/error_code.hpp>

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <string>
#include <utility>
#include <vector>

enum class ClientError {
    none,
    already_started,
    write_failed,
    header_read_failed,
    invalid_header,
    payload_read_failed,
    invalid_crc,
    unexpected_packet_id
};

// Connection is a compile-time interface. It must provide:
//   async_write(vector<char>, handler(error_code, size_t))
//   async_read_exactly(size_t, handler(error_code, vector<char>))
//   close()
template <typename Connection>
class BasicClient {
public:
    explicit BasicClient(Connection& connection) : connection_(connection) {}

    void send_packets(int count) {
        if (active_) {
            error_ = ClientError::already_started;
            return;
        }

        packets_sent_ = 0;
        packets_received_ = 0;
        packets_to_send_ = count > 0 ? count : 0;
        error_ = ClientError::none;
        complete_ = packets_to_send_ == 0;
        active_ = !complete_;

        if (active_) {
            send_next_packet();
        }
    }

    int packets_sent() const { return packets_sent_; }
    int packets_received() const { return packets_received_; }
    bool complete() const { return complete_; }
    bool active() const { return active_; }
    ClientError error() const { return error_; }

private:
    void send_next_packet() {
        const int packet_number = packets_sent_;
        const std::string payload =
            "Hello from C++ Client, packet #" + std::to_string(packet_number);
        auto bytes = Packet(100U + static_cast<uint32_t>(packet_number), payload).serialize();

        connection_.async_write(std::move(bytes),
            [this](const boost::system::error_code& error, std::size_t) {
                if (error) {
                    fail(ClientError::write_failed);
                    return;
                }
                ++packets_sent_;
                read_header();
            });
    }

    void read_header() {
        connection_.async_read_exactly(sizeof(PacketHeader),
            [this](const boost::system::error_code& error, std::vector<char> header) {
                if (error) {
                    fail(ClientError::header_read_failed);
                    return;
                }
                if (header.size() != sizeof(PacketHeader)) {
                    fail(ClientError::invalid_header);
                    return;
                }

                PacketHeader decoded{};
                std::memcpy(&decoded, header.data(), sizeof(decoded));
                const std::size_t payload_size = ntohs(decoded.len);
                read_payload(std::move(header), payload_size);
            });
    }

    void read_payload(std::vector<char> header, std::size_t payload_size) {
        connection_.async_read_exactly(payload_size,
            [this, header = std::move(header), payload_size](
                const boost::system::error_code& error, std::vector<char> payload) {
                if (error) {
                    fail(ClientError::payload_read_failed);
                    return;
                }
                if (payload.size() != payload_size) {
                    fail(ClientError::invalid_header);
                    return;
                }

                try {
                    Packet packet = Packet::deserialize(
                        header.data(), header.size(),
                        std::string(payload.begin(), payload.end()));
                    if (!packet.verify_crc()) {
                        fail(ClientError::invalid_crc);
                        return;
                    }
                    const uint32_t expected_id =
                        100U + static_cast<uint32_t>(packets_received_);
                    if (packet.id() != expected_id) {
                        fail(ClientError::unexpected_packet_id);
                        return;
                    }
                } catch (const std::exception&) {
                    fail(ClientError::invalid_header);
                    return;
                }

                ++packets_received_;
                if (packets_received_ == packets_to_send_) {
                    active_ = false;
                    complete_ = true;
                    connection_.close();
                    return;
                }
                send_next_packet();
            });
    }

    void fail(ClientError error) {
        error_ = error;
        active_ = false;
        complete_ = false;
    }

    Connection& connection_;
    int packets_sent_ = 0;
    int packets_received_ = 0;
    int packets_to_send_ = 0;
    bool active_ = false;
    bool complete_ = false;
    ClientError error_ = ClientError::none;
};
