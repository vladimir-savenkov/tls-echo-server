#pragma once

#include "protocol.h"
#include "log_payload.h"

#include <boost/system/error_code.hpp>

#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
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

inline const char* client_error_name(ClientError error) {
    switch (error) {
        case ClientError::none: return "none";
        case ClientError::already_started: return "already_started";
        case ClientError::write_failed: return "write_failed";
        case ClientError::header_read_failed: return "header_read_failed";
        case ClientError::invalid_header: return "invalid_header";
        case ClientError::payload_read_failed: return "payload_read_failed";
        case ClientError::invalid_crc: return "invalid_crc";
        case ClientError::unexpected_packet_id: return "unexpected_packet_id";
    }
    return "unknown";
}

// Connection is a compile-time interface. It must provide:
//   async_write(vector<char>, handler(error_code, size_t))
//   async_read_exactly(size_t, handler(error_code, vector<char>))
//   close()
template <typename Connection>
class BasicClient {
public:
    explicit BasicClient(Connection& connection,
                         std::function<void(const std::string&)> state_callback = {})
        : connection_(connection), state_callback_(std::move(state_callback)) {}

    void send_packets(int count) {
        if (active_) {
            error_ = ClientError::already_started;
            if (state_callback_) log_state("request sequence rejected: already active");
            return;
        }

        packets_sent_ = 0;
        packets_received_ = 0;
        packets_to_send_ = count > 0 ? count : 0;
        error_ = ClientError::none;
        complete_ = packets_to_send_ == 0;
        active_ = !complete_;
        if (state_callback_) {
            log_state("request sequence started: target=" + std::to_string(packets_to_send_));
        }

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
        if (state_callback_) {
            log_state("sending packet=" + std::to_string(packet_number + 1) +
                      "/" + std::to_string(packets_to_send_) +
                      ", id=" + std::to_string(100U + packet_number) +
                      ", data=\"" + escape_log_payload(payload) + "\"");
        }

        connection_.async_write(std::move(bytes),
            [this](const boost::system::error_code& error, std::size_t bytes_written) {
                if (state_callback_) {
                    log_state("write callback: bytes=" + std::to_string(bytes_written) +
                              ", status=" + (error ? error.message() : "ok"));
                }
                if (error) {
                    fail(ClientError::write_failed);
                    return;
                }
                ++packets_sent_;
                if (state_callback_) {
                    log_state("packet sent: total=" + std::to_string(packets_sent_));
                }
                read_header();
            });
    }

    void read_header() {
        if (state_callback_) log_state("waiting for response header");
        connection_.async_read_exactly(sizeof(PacketHeader),
            [this](const boost::system::error_code& error, std::vector<char> header) {
                if (state_callback_) {
                    log_state("header callback: bytes=" + std::to_string(header.size()) +
                              ", status=" + (error ? error.message() : "ok"));
                }
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
                if (state_callback_) {
                    log_state("response header parsed: id=" + std::to_string(ntohl(decoded.id)) +
                              ", payload_bytes=" + std::to_string(payload_size));
                }
                read_payload(std::move(header), payload_size);
            });
    }

    void read_payload(std::vector<char> header, std::size_t payload_size) {
        if (state_callback_) {
            log_state("waiting for response payload: bytes=" + std::to_string(payload_size));
        }
        connection_.async_read_exactly(payload_size,
            [this, header = std::move(header), payload_size](
                const boost::system::error_code& error, std::vector<char> payload) {
                if (state_callback_) {
                    log_state("payload callback: bytes=" + std::to_string(payload.size()) +
                              ", status=" + (error ? error.message() : "ok"));
                }
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
                    if (state_callback_) {
                        log_state("received packet=" + std::to_string(packets_received_ + 1) +
                                  "/" + std::to_string(packets_to_send_) +
                                  ", id=" + std::to_string(packet.id()) +
                                  ", data=\"" + escape_log_payload(packet.payload()) + "\"");
                    }
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
                if (state_callback_) {
                    log_state("response validated: received=" + std::to_string(packets_received_) +
                              "/" + std::to_string(packets_to_send_));
                }
                if (packets_received_ == packets_to_send_) {
                    active_ = false;
                    complete_ = true;
                    if (state_callback_) log_state("request sequence complete; closing connection");
                    connection_.close();
                    return;
                }
                send_next_packet();
            });
    }

    void fail(ClientError error) {
        if (state_callback_) {
            log_state(std::string("request sequence failed: error=") + client_error_name(error));
        }
        error_ = error;
        active_ = false;
        complete_ = false;
    }

    void log_state(const std::string& state) const {
        if (state_callback_) {
            state_callback_(state);
        }
    }

    Connection& connection_;
    std::function<void(const std::string&)> state_callback_;
    int packets_sent_ = 0;
    int packets_received_ = 0;
    int packets_to_send_ = 0;
    bool active_ = false;
    bool complete_ = false;
    ClientError error_ = ClientError::none;
};
