#pragma once

#include "protocol.h"
#include "log_payload.h"
#include "latency_stats.h"
#include <chrono>
#include <optional>
#include <stdexcept>

#include <boost/system/error_code.hpp>

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
    unexpected_packet_id,
    unexpected_payload
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
        case ClientError::unexpected_payload: return "unexpected_payload";
    }
    return "unknown";
}

struct ClientRunOptions {
    std::optional<std::size_t> payload_size;
    std::chrono::milliseconds duration{0};
};

// Connection is a compile-time interface. It must provide:
//   async_write(vector<char>, handler(error_code, size_t))
//   async_read_exactly(size_t, handler(error_code, vector<char>))
//   close() / abort()
template <typename Connection>
class BasicClient {
public:
    explicit BasicClient(Connection& connection,
                         std::function<void(const std::string&)> state_callback = {},
                         std::function<void(ClientError)> completion_callback = {},
                         ClientRunOptions options = {})
        : connection_(connection), state_callback_(std::move(state_callback)),
          completion_callback_(std::move(completion_callback)), options_(options) {
        if ((options_.payload_size && *options_.payload_size > 65535) ||
            options_.duration.count() < 0) {
            throw std::invalid_argument("Invalid client run options");
        }
    }

    void send_packets(int count) {
        if (active_) {
            error_ = ClientError::already_started;
            if (state_callback_) log_state("request sequence rejected: already active");
            return;
        }

        notified_ = false;
        latency_ = {};
        bytes_received_ = 0;
        run_started_ = std::chrono::steady_clock::now();
        packets_sent_ = 0;
        packets_received_ = 0;
        packets_to_send_ = count > 0 ? static_cast<uint64_t>(count) : 0;
        error_ = ClientError::none;
        complete_ = packets_to_send_ == 0 && options_.duration.count() == 0;
        active_ = !complete_;
        if (state_callback_) {
            log_state("request sequence started: target=" + std::to_string(packets_to_send_));
        }

        if (active_) {
            send_next_packet();
        } else {
            connection_.close();
            notify();
        }
    }

    uint64_t packets_sent() const { return packets_sent_; }
    uint64_t packets_received() const { return packets_received_; }
    bool complete() const { return complete_; }
    bool active() const { return active_; }
    ClientError error() const { return error_; }
    uint64_t bytes_received() const { return bytes_received_; }
    const LatencyStats& latency() const { return latency_; }

private:
    void send_next_packet() {
        const auto packet_number = packets_sent_;
        expected_payload_ = "Hello from C++ Client, packet #" + std::to_string(packet_number);
        if (options_.payload_size) {
            expected_payload_.resize(*options_.payload_size);
            for (std::size_t i = 0; i < expected_payload_.size(); ++i) {
                expected_payload_[i] = static_cast<char>((i + packet_number) % 256);
            }
        }
        request_started_ = std::chrono::steady_clock::now();
        auto bytes = Packet(100U + static_cast<uint32_t>(packet_number), expected_payload_).serialize();
        if (state_callback_) {
            log_state("sending packet=" + std::to_string(packet_number + 1) +
                      "/" + std::to_string(packets_to_send_) +
                      ", id=" + std::to_string(100U + packet_number) +
                      ", data=\"" + escape_log_payload(expected_payload_) + "\"");
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
                const std::size_t payload_size = wire::from_network16(decoded.len);
                if (state_callback_) {
                    log_state("response header parsed: id=" + std::to_string(wire::from_network32(decoded.id)) +
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
                    if (packet.payload() != expected_payload_) {
                        fail(ClientError::unexpected_payload);
                        return;
                    }
                } catch (const std::exception&) {
                    fail(ClientError::invalid_header);
                    return;
                }

                ++packets_received_;
                bytes_received_ += payload.size();
                const auto now = std::chrono::steady_clock::now();
                latency_.record(std::chrono::duration<double, std::micro>(now - request_started_).count());
                if (state_callback_) {
                    log_state("response validated: received=" + std::to_string(packets_received_) +
                              "/" + std::to_string(packets_to_send_));
                }
                if (options_.duration.count() > 0
                        ? now - run_started_ >= options_.duration
                        : packets_received_ == packets_to_send_) {
                    active_ = false;
                    complete_ = true;
                    if (state_callback_) log_state("request sequence complete; closing connection");
                    connection_.close();
                    notify();
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
        connection_.abort();
        notify();
    }

    void notify() {
        if (notified_) return;
        notified_ = true;
        if (completion_callback_) completion_callback_(error_);
    }

    void log_state(const std::string& state) const {
        if (state_callback_) {
            state_callback_(state);
        }
    }

    Connection& connection_;
    std::function<void(const std::string&)> state_callback_;
    std::function<void(ClientError)> completion_callback_;
    ClientRunOptions options_;
    std::string expected_payload_;
    std::chrono::steady_clock::time_point request_started_, run_started_;
    LatencyStats latency_;
    uint64_t bytes_received_ = 0;
    uint64_t packets_sent_ = 0;
    uint64_t packets_received_ = 0;
    uint64_t packets_to_send_ = 0;
    bool notified_ = false;
    bool active_ = false;
    bool complete_ = false;
    ClientError error_ = ClientError::none;
};
