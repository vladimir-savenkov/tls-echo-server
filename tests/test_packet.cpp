#include "protocol.h"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <limits>
#include <random>
#include <stdexcept>
#include <string>

namespace {
int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

template <typename Exception, typename Function>
void check_throws(Function function, const char* message) {
    try {
        function();
        check(false, message);
    } catch (const Exception&) {
    } catch (...) {
        check(false, message);
    }
}

void test_crc32_known_vectors() {
    check(calculate_crc32(nullptr, 0) == 0U, "CRC32 of empty input");
    const std::string standard = "123456789";
    check(calculate_crc32(standard.data(), standard.size()) == 0xCBF43926U,
          "CRC32 standard check vector");
    const std::string binary{"\0\x80\xff\0", 4};
    check(calculate_crc32(binary.data(), binary.size()) == 0x535539EEU,
          "CRC32 handles arbitrary binary data");
    check_throws<std::invalid_argument>(
        [] { calculate_crc32(nullptr, 1); }, "CRC32 rejects null non-empty input");
}

void test_construction_and_serialization() {
    const std::string payload{"hello\0world", 11};
    const Packet packet(0x01020304U, payload);
    check(packet.id() == 0x01020304U, "constructor preserves id");
    check(packet.payload() == payload, "constructor preserves binary payload");
    check(packet.length() == payload.size(), "packet reports payload length");
    check(packet.verify_crc(), "new packet has valid CRC");

    const auto bytes = packet.serialize();
    check(bytes.size() == sizeof(PacketHeader) + payload.size(),
          "serialized size contains header and payload");
    PacketHeader header{};
    std::memcpy(&header, bytes.data(), sizeof(header));
    check(ntohl(header.id) == packet.id(), "id uses network byte order");
    check(ntohs(header.len) == payload.size(), "length uses network byte order");
    check(ntohl(header.crc) == packet.crc(), "CRC uses network byte order");
    check(std::string(bytes.data() + sizeof(header), payload.size()) == payload,
          "serialization preserves payload bytes");
}

void test_round_trip_and_corruption() {
    const Packet original(42U, "payload");
    const auto bytes = original.serialize();
    const std::string payload(bytes.data() + sizeof(PacketHeader), original.length());
    const Packet decoded = Packet::deserialize(bytes.data(), sizeof(PacketHeader), payload);
    check(decoded.id() == original.id(), "round trip preserves id");
    check(decoded.payload() == original.payload(), "round trip preserves payload");
    check(decoded.crc() == original.crc(), "round trip preserves CRC");
    check(decoded.verify_crc(), "round-tripped packet verifies");

    std::string corrupted = payload;
    corrupted[0] ^= 1;
    const Packet damaged(original.id(), static_cast<uint16_t>(corrupted.size()),
                         original.crc(), corrupted);
    check(!damaged.verify_crc(), "payload corruption is detected");
}

void test_invalid_input_and_boundaries() {
    check_throws<std::length_error>(
        [] { Packet packet(1U, std::string(65536, 'x')); },
        "oversized payload is rejected");
    check_throws<std::invalid_argument>(
        [] { Packet packet(1U, 2U, 0U, "x"); },
        "mismatched payload length is rejected");

    PacketHeader header{};
    header.id = htonl(1U);
    header.len = htons(2U);
    check_throws<std::invalid_argument>(
        [&] { Packet::deserialize(nullptr, sizeof(header), "xx"); },
        "null header is rejected");
    check_throws<std::invalid_argument>(
        [&] { Packet::deserialize(reinterpret_cast<const char*>(&header), sizeof(header) - 1, "xx"); },
        "undersized header is rejected");
    check_throws<std::invalid_argument>(
        [&] { Packet::deserialize(reinterpret_cast<const char*>(&header), sizeof(header), "x"); },
        "header and payload length mismatch is rejected");

    const Packet maximum(1U, std::string(std::numeric_limits<uint16_t>::max(), 'x'));
    check(maximum.length() == std::numeric_limits<uint16_t>::max(),
          "maximum payload length is accepted");
}

void test_defaults_golden_bytes_and_random_round_trips() {
    const Packet empty;
    check(empty.id() == 0U && empty.length() == 0U && empty.verify_crc(),
          "default packet is a valid empty packet");

    const Packet golden(0x01020304U, "123456789");
    const std::vector<char> expected{
        0x01, 0x02, 0x03, 0x04, 0x00, 0x09,
        static_cast<char>(0xCB), static_cast<char>(0xF4), 0x39, 0x26,
        '1', '2', '3', '4', '5', '6', '7', '8', '9'};
    check(golden.serialize() == expected, "packet matches the golden wire format");
    check(golden.serialize() == golden.serialize(), "serialization is deterministic");

    std::mt19937 generator(0xC0FFEEU);
    std::uniform_int_distribution<int> length_distribution(0, 512);
    std::uniform_int_distribution<int> byte_distribution(0, 255);
    for (int iteration = 0; iteration < 100; ++iteration) {
        std::string payload(static_cast<std::size_t>(length_distribution(generator)), '\0');
        for (char& byte : payload) {
            byte = static_cast<char>(byte_distribution(generator));
        }
        const uint32_t id = generator();
        const Packet original(id, payload);
        const auto bytes = original.serialize();
        const Packet decoded = Packet::deserialize(
            bytes.data(), sizeof(PacketHeader),
            std::string(bytes.begin() + sizeof(PacketHeader), bytes.end()));
        check(decoded.id() == id && decoded.payload() == payload && decoded.verify_crc(),
              "randomized packet round trip");
    }
}
}  // namespace

int main() {
    test_crc32_known_vectors();
    test_construction_and_serialization();
    test_round_trip_and_corruption();
    test_invalid_input_and_boundaries();
    test_defaults_golden_bytes_and_random_round_trips();
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All Packet tests passed\n";
    return 0;
}
