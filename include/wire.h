#pragma once

#include <array>
#include <cstdint>
#include <cstring>

// Преобразования не зависят от POSIX/Winsock и порядка байтов процессора.
namespace wire {
inline uint16_t to_network16(uint16_t value) {
    const std::array<unsigned char, 2> bytes = {static_cast<unsigned char>(value >> 8),
                                                static_cast<unsigned char>(value)};
    uint16_t result;
    std::memcpy(&result, bytes.data(), sizeof(result));
    return result;
}
inline uint32_t to_network32(uint32_t value) {
    const std::array<unsigned char, 4> bytes = {static_cast<unsigned char>(value >> 24),
        static_cast<unsigned char>(value >> 16), static_cast<unsigned char>(value >> 8),
        static_cast<unsigned char>(value)};
    uint32_t result;
    std::memcpy(&result, bytes.data(), sizeof(result));
    return result;
}
inline uint16_t from_network16(uint16_t value) {
    std::array<unsigned char, 2> bytes;
    std::memcpy(bytes.data(), &value, sizeof(value));
    return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}
inline uint32_t from_network32(uint32_t value) {
    std::array<unsigned char, 4> bytes;
    std::memcpy(bytes.data(), &value, sizeof(value));
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) | bytes[3];
}
}  // namespace wire
