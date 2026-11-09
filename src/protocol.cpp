#include "protocol.h"

#include <array>
#include <cstddef>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace {

// Таблица CRC32 (полином zlib 0xEDB88320, отражённый). Вычисляется во время
// компиляции тем же побитовым алгоритмом — эталон и таблица не могут
// разойтись. Табличный вариант даёт тот же результат одним XOR и сдвигом
// на байт вместо 8 итераций внутреннего цикла.
constexpr std::array<uint32_t, 256> make_crc32_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
        table[i] = crc;
    }
    return table;
}

constexpr auto crc32_table = make_crc32_table();

}  // namespace

uint32_t calculate_crc32(const char* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        throw std::invalid_argument("CRC input is null");
    }

    uint32_t crc = 0xFFFFFFFFU;
    for (std::size_t i = 0; i < size; ++i) {
        crc = (crc >> 8U) ^
              crc32_table[(crc ^ static_cast<unsigned char>(data[i])) & 0xFFU];
    }
    return crc ^ 0xFFFFFFFFU;
}

Packet::Packet(uint32_t id, const std::string& payload)
    : id_(id), payload_(payload) {
    if (payload.size() > std::numeric_limits<uint16_t>::max()) {
        throw std::length_error("Packet payload exceeds 65535 bytes");
    }
    update_crc();
}

Packet::Packet(uint32_t id, uint16_t len, uint32_t crc,
               const std::string& payload)
    : id_(id), crc_(crc), payload_(payload) {
    if (len != payload.size()) {
        throw std::invalid_argument("Packet header length does not match payload size");
    }
}

void Packet::update_crc() {
    crc_ = calculate_crc32(payload_.data(), payload_.size());
}

std::vector<char> Packet::serialize() const {
    PacketHeader header{};
    header.id = wire::to_network32(id_);
    header.len = wire::to_network16(length());
    header.crc = wire::to_network32(crc_);

    std::vector<char> buffer(sizeof(header) + payload_.size());
    std::memcpy(buffer.data(), &header, sizeof(header));
    if (!payload_.empty()) {
        std::memcpy(buffer.data() + sizeof(header), payload_.data(), payload_.size());
    }
    return buffer;
}

Packet Packet::deserialize(const char* raw_header, std::size_t header_size,
                           const std::string& payload) {
    if (raw_header == nullptr) {
        throw std::invalid_argument("Packet header is null");
    }
    if (header_size != sizeof(PacketHeader)) {
        throw std::invalid_argument("Packet header must be exactly 10 bytes");
    }

    PacketHeader header{};
    std::memcpy(&header, raw_header, sizeof(header));
    return Packet(wire::from_network32(header.id), wire::from_network16(header.len), wire::from_network32(header.crc), payload);
}

bool Packet::verify_crc() const {
    return calculate_crc32(payload_.data(), payload_.size()) == crc_;
}
