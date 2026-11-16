#pragma once

#include "protocol.h"
#include "log_payload.h"
#include "latency_stats.h"
#include <chrono>
#include <deque>
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

enum class ClientError : std::uint8_t {
    none,
    already_started,
    write_failed,
    header_read_failed,
    invalid_header,
    payload_read_failed,
    invalid_crc,
    unexpected_packet_id,
    unexpected_payload,
    server_rejected
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
        case ClientError::server_rejected: return "server_rejected";
    }
    return "unknown";
}

// Предел окна pipelining: защищает от бессмысленно длинных очередей in-flight.
inline constexpr std::size_t max_client_window = 1024;

struct ClientRunOptions {
    std::optional<std::size_t> payload_size;
    std::chrono::milliseconds duration{0};
    // Число запросов в полёте без ответа; больше единицы включает
    // pipelining и действует только в режиме duration.
    std::size_t window = 8;
};

// Эффективное окно: в счётном режиме — строго один запрос в полёте.
inline std::size_t effective_window(const ClientRunOptions& options) {
    return options.duration.count() > 0 ? options.window : std::size_t{1};
}

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
            options_.duration.count() < 0 ||
            options_.window == 0 || options_.window > max_client_window) {
            throw std::invalid_argument("Invalid client run options");
        }
        // Pipelining действует только в режиме длительности: счётный режим
        // сохраняет строгий запрос/ответ ради честных измерений задержки.
        window_ = effective_window(options_);
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
        server_error_code_ = 0;
        inflight_started_.clear();
        inflight_payloads_.clear();
        write_outstanding_ = false;
        reading_ = false;
        complete_ = packets_to_send_ == 0 && options_.duration.count() == 0;
        active_ = !complete_;
        if (state_callback_) {
            log_state("request sequence started: target=" + std::to_string(packets_to_send_) +
                      ", window=" + std::to_string(window_));
        }

        if (active_) {
            maybe_send();
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
    // Код из пакета-уведомления; осмыслен при error() == server_rejected.
    uint32_t server_error_code() const { return server_error_code_; }
    uint64_t bytes_received() const { return bytes_received_; }
    const LatencyStats& latency() const { return latency_; }
    // Эффективное окно запросов в полёте (в счётном режиме — всегда 1).
    std::size_t window() const { return window_; }

private:
    // Отправляет запросы, пока есть место в окне и причины отправлять.
    // Записи строго последовательны (один async_write в полёте): параллельные
    // записи в один сокет недопустимы, окно ограничивает запросы без ответа.
    void maybe_send() {
        if (!active_ || write_outstanding_) return;
        if (inflight_payloads_.size() >= window_) return;
        if (options_.duration.count() > 0) {
            // Режим длительности: после истечения срока новые запросы
            // не отправляются — дорабатываются только уже отправленные.
            if (std::chrono::steady_clock::now() - run_started_ >= options_.duration) return;
        } else if (packets_sent_ >= packets_to_send_) {
            return;
        }
        send_next_packet();
    }

    void send_next_packet() {
        const auto packet_number = packets_sent_;
        std::string payload = "Hello from C++ Client, packet #" + std::to_string(packet_number);
        if (options_.payload_size) {
            payload.resize(*options_.payload_size);
            for (std::size_t i = 0; i < payload.size(); ++i) {
                payload[i] = static_cast<char>((i + packet_number) % 256);
            }
        }
        // Метка и ожидаемая нагрузка уходят в очередь in-flight: при окне > 1
        // ответ сверяется со своим запросом, а не с последним отправленным.
        inflight_started_.push_back(std::chrono::steady_clock::now());
        inflight_payloads_.push_back(std::move(payload));
        write_outstanding_ = true;
        auto bytes = Packet(100U + static_cast<uint32_t>(packet_number),
                            inflight_payloads_.back()).serialize();
        if (state_callback_) {
            log_state("sending packet=" + std::to_string(packet_number + 1) +
                      "/" + std::to_string(packets_to_send_) +
                      ", id=" + std::to_string(100U + packet_number) +
                      ", data=\"" + escape_log_payload(inflight_payloads_.back()) + "\"");
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
                write_outstanding_ = false;
                if (state_callback_) {
                    log_state("packet sent: total=" + std::to_string(packets_sent_));
                }
                // Цепочка чтения одна и стартует с первой завершённой записи;
                // дальше она живёт, пока есть запросы без ответа.
                if (!reading_ && !inflight_payloads_.empty()) {
                    reading_ = true;
                    read_header();
                }
                maybe_send();
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
                // Чужой формат заголовка: не читаем мусорную длину payload,
                // падаем сразу; deserialize ниже продублирует проверку.
                if (wire::from_network16(decoded.magic) != protocol_magic ||
                    decoded.version != protocol_version ||
                    (decoded.flags & ~protocol_flag_error) != 0) {
                    fail(ClientError::invalid_header);
                    return;
                }
                // Уведомление об ошибке: сервер отверг запрос и закрывает
                // соединение; нагрузка у уведомления запрещена — payload не читаем.
                if ((decoded.flags & protocol_flag_error) != 0) {
                    if (wire::from_network16(decoded.len) != 0) {
                        fail(ClientError::invalid_header);
                        return;
                    }
                    server_error_code_ = wire::from_network32(decoded.id);
                    if (state_callback_) {
                        log_state("server rejected the packet: error=" +
                                  packet_error_name(server_error_code_));
                    }
                    fail(ClientError::server_rejected);
                    return;
                }
                const std::size_t payload_size = wire::from_network16(decoded.len);
                if (state_callback_) {
                    log_state("response header parsed: id=" + std::to_string(wire::from_network32(decoded.id)) +
                              ", payload_bytes=" + std::to_string(payload_size));
                }
                read_payload(std::move(header), payload_size);
            });
    }

    // Линейная цепочка проверок ответа «заголовок → payload → сверка»;
    // разбиение на помощники усложнит чтение последовательности — сложность
    // осознанно принята.
    void read_payload(std::vector<char> header, std::size_t payload_size) {  // NOLINT(readability-function-cognitive-complexity)
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
                    if (packet.payload() != inflight_payloads_.front()) {
                        fail(ClientError::unexpected_payload);
                        return;
                    }
                } catch (const std::exception&) {
                    fail(ClientError::invalid_header);
                    return;
                }

                ++packets_received_;
                bytes_received_ += payload.size();
                // Задержка — от метки отправки своего запроса: очередь in-flight
                // параллельна, ответы приходят в порядке отправки (FIFO).
                const auto started = inflight_started_.front();
                inflight_started_.pop_front();
                inflight_payloads_.pop_front();
                const auto now = std::chrono::steady_clock::now();
                latency_.record(std::chrono::duration<double, std::micro>(now - started).count());
                if (state_callback_) {
                    log_state("response validated: received=" + std::to_string(packets_received_) +
                              "/" + std::to_string(packets_to_send_));
                }
                // Завершение: счётный режим — получены все ответы; режим
                // длительности — срок истёк и окно in-flight пустое
                // (отправленные запросы доработаны до полных ответов).
                const bool done = options_.duration.count() > 0
                    ? (now - run_started_ >= options_.duration && inflight_payloads_.empty())
                    : packets_received_ == packets_to_send_;
                if (done) {
                    active_ = false;
                    complete_ = true;
                    if (state_callback_) log_state("request sequence complete; closing connection");
                    connection_.close();
                    notify();
                    return;
                }
                if (inflight_payloads_.empty()) {
                    reading_ = false;  // новых ответов нет — цепочка возобновится после следующей записи
                } else {
                    read_header();    // ответы ещё в полёте — читаем дальше
                }
                maybe_send();
            });
    }

    void fail(ClientError error) {
        // Отменённые после abort() операции (при окне > 1 запись и чтение
        // висят одновременно) не переписывают причину: остаётся первая ошибка.
        if (!active_) return;
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
    std::size_t window_ = 1;
    std::deque<std::chrono::steady_clock::time_point> inflight_started_;
    std::deque<std::string> inflight_payloads_;
    std::chrono::steady_clock::time_point run_started_;
    LatencyStats latency_;
    uint64_t bytes_received_ = 0;
    uint64_t packets_sent_ = 0;
    uint64_t packets_received_ = 0;
    uint64_t packets_to_send_ = 0;
    bool write_outstanding_ = false;
    bool reading_ = false;
    bool notified_ = false;
    bool active_ = false;
    bool complete_ = false;
    ClientError error_ = ClientError::none;
    uint32_t server_error_code_ = 0;
};
