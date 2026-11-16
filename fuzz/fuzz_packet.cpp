// Точка входа libFuzzer для парсера пакетов. Вход трактуется как сырой кадр
// с провода: первые sizeof(PacketHeader) байт — заголовок, остальное —
// полезная нагрузка. Сборка и запуск: scripts/fuzz_packet.sh.
#include "protocol.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size) {
    // Вспомогательные функции не должны падать ни на каких входных данных.
    uint32_t error_code = 0;
    if (size >= sizeof(error_code)) {
        std::memcpy(&error_code, data, sizeof(error_code));
    }
    packet_error_name(error_code);
    calculate_crc32(reinterpret_cast<const char*>(data), size);

    if (size < sizeof(PacketHeader)) {
        return 0;
    }
    const std::string payload(reinterpret_cast<const char*>(data) + sizeof(PacketHeader),
                              size - sizeof(PacketHeader));
    try {
        const Packet packet = Packet::deserialize(reinterpret_cast<const char*>(data),
                                                  sizeof(PacketHeader), payload);
        // Инвариант round-trip: принятый пакет сериализуется обратно в те же
        // байты — заголовок переносит id/len/crc/flags как есть, а конструктор
        // уже гарантировал len == payload.size().
        const std::vector<char> bytes = packet.serialize();
        if (bytes.size() != size || std::memcmp(bytes.data(), data, size) != 0) {
            std::abort();  // сериализация не воспроизвела принятый кадр
        }
        // verify_crc() обязан быть чистым предикатом без побочных эффектов.
        packet.verify_crc();
    } catch (const std::invalid_argument&) {
        // Ожидаемый отказ протокола: чужой magic/версия/флаги, len не совпал
        // с размером нагрузки, пакет-уведомление с непустой нагрузкой.
    }
    return 0;
}
