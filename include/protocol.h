#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

// ============================================================================
// 1. Структура заголовка (Binary Layout)
// ============================================================================

#pragma pack(push, 1)
struct PacketHeader {
    uint32_t id;
    uint16_t len;
    uint32_t crc;
};
#pragma pack(pop)

static_assert(sizeof(PacketHeader) == 10, 
              "PacketHeader must be exactly 10 bytes");

// ============================================================================
// 2. Класс Packet (Публичный интерфейс)
// ============================================================================

class Packet {
public:
    Packet() = default;
    
    // Конструктор для отправки (автоматический расчет CRC)
    Packet(uint32_t id, const std::string& payload);

    // Конструктор для приема (данные уже загружены)
    Packet(uint32_t id, uint16_t len, uint32_t crc, const std::string& payload);

    // Сериализация в буфер для отправки
    std::vector<char> serialize() const;

    // Десериализация из сырых данных
    static Packet deserialize(const char* raw_header, const std::string& payload);

    // Проверка контрольной суммы
    bool verify_crc() const;

    // Геттеры
    uint32_t id() const { return id_; }
    const std::string& payload() const { return payload_; }
    uint32_t crc() const { return crc_; }

private:
    void update_crc();

    uint32_t id_ = 0;
    uint32_t crc_ = 0;
    std::string payload_;
};

// ============================================================================
// 3. Отдельная функция для расчета CRC (если нужна снаружи)
// ============================================================================
uint32_t calculate_crc32(const char* data, std::size_t size);

