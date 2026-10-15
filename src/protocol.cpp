#include "protocol.h"

#include <arpa/inet.h>
#include <cstring>
#include <limits>
#include <stdexcept>

uint32_t calculate_crc32(const char* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        throw std::invalid_argument("CRC input is null");
    }

    uint32_t crc = 0xFFFFFFFFU;
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= static_cast<unsigned char>(data[i]);
        for (int bit = 0; bit < 8; ++bit) {
            const uint32_t mask = -(crc & 1U);
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
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
    header.id = htonl(id_);
    header.len = htons(length());
    header.crc = htonl(crc_);

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
    return Packet(ntohl(header.id), ntohs(header.len), ntohl(header.crc), payload);
}

bool Packet::verify_crc() const {
    return calculate_crc32(payload_.data(), payload_.size()) == crc_;
}
