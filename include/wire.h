#pragma once

#include <cstdint>
#include <cstring>

// Преобразования не зависят от POSIX/Winsock и порядка байтов процессора.
namespace wire {
inline uint16_t to_network16(uint16_t value) {
    const unsigned char bytes[] = {static_cast<unsigned char>(value >> 8),
                                   static_cast<unsigned char>(value)};
    uint16_t result;
    std::memcpy(&result, bytes, sizeof(result));
    return result;
}
inline uint32_t to_network32(uint32_t value) {
    const unsigned char bytes[] = {static_cast<unsigned char>(value >> 24),
        static_cast<unsigned char>(value >> 16), static_cast<unsigned char>(value >> 8),
        static_cast<unsigned char>(value)};
    uint32_t result;
    std::memcpy(&result, bytes, sizeof(result));
    return result;
}
inline uint16_t from_network16(uint16_t value) {
    unsigned char bytes[2];
    std::memcpy(bytes, &value, sizeof(value));
    return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) | bytes[1]);
}
inline uint32_t from_network32(uint32_t value) {
    unsigned char bytes[4];
    std::memcpy(bytes, &value, sizeof(value));
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) | bytes[3];
}
}  // namespace wire
