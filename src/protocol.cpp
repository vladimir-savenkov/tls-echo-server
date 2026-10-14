nclude "protocol.h"
#include <cstring>
#include <cstdint>

// ============================================================================
// 1. Таблица CRC32 (Static, живет только в этой единице трансляции)
// ============================================================================

namespace {
    static const unsigned int crc_table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
        0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
        0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
        0x3B6E0522, 0x4C6935B4, 0xD560640E, 0xA2675498, 0x3C03C53B, 0x4B04F5AD, 0xD20DA417, 0xA50A9481,
        0x35B5A9F0, 0x42B29966, 0xFBBBC8DE, 0x8CB8F848, 0x32D86DEB, 0x45DF5D7D, 0xDCD60CC7, 0xABD13C51,
        0x26D936C4, 0x51DE0652, 0xC8D757E8, 0xBFD0677E, 0x21B4F6DD, 0x56B3C64B, 0xCFBA97F1, 0xB8BDA767,
        0x2802B5F6, 0x5F058560, 0xC60CD4DA, 0xB10BE44C, 0x2F6F750F, 0x58684599, 0xC1611423, 0xB66624B5,
        0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x706AF48D, 0x076DC41B, 0x9E6495A1, 0xE963A537,
        0x79DCB8A6, 0x0EDB8830, 0x97D2D98A, 0x80D5E91C, 0x71B16C93, 0x06B65C05, 0x9FBFE9BF, 0xA8B8D929,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
        0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
        0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26152, 0x3AB551C4, 0xA3BC007E, 0xD4BB30E8, 0x4ADFA14B, 0x3DD891DD, 0xA4D1C067, 0xD3D6F0F1,
        0x4369E860, 0x346ED8F6, 0xAD67894C, 0xDA60B9DA, 0x44042D79, 0x33031DEE, 0xAA0A4C54, 0xD90D7CC2,
        0x47B76053, 0x30B050C5, 0xA9B9017F, 0xDEBE31E9, 0x4E6AA44A, 0x396D94DC, 0xA064C566, 0xD763F5F0,
        0x49D91B7B, 0x3EDE2BEB, 0xA7D77A51, 0xD0D04AC7, 0x40B4D866, 0x37B3E8F0, 0xAEBAB94A, 0xD9BD89DC,
        0x3B6E0522, 0x4C6935B4, 0xD560640E, 0xA2675498, 0x3C03C53B, 0x4B04F5AD, 0xD20DA417, 0xA50A9481
    };
}

// ============================================================================
// 2. Реализация CRC32
// ============================================================================

uint32_t calculate_crc32(const char* data, std::size_t size) {
    uint32_t crc = 0xFFFFFFFFUL;
    for (std::size_t i = 0; i < size; ++i) {
        unsigned char byte = static_cast<unsigned char>(data[i]);
        crc = crc_table[(crc ^ byte) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFUL;
}

// ============================================================================
// 3. Реализация методов класса Packet
// ============================================================================

Packet::Packet(uint32_t id, const std::string& payload) 
    : id_(id), payload_(payload) {
    update_crc();
}

Packet::Packet(uint32_t id, uint16_t len, uint32_t crc, const std::string& payload)
    : id_(id), crc_(crc), payload_(payload) {}

void Packet::update_crc() {
    crc_ = calculate_crc32(payload_.c_str(), payload_.size());
}

std::vector<char> Packet::serialize() const {
    std::vector<char> buffer;
    buffer.reserve(sizeof(PacketHeader) + payload_.size());

    PacketHeader hdr;
    hdr.id = htonl(id_);
    hdr.len = htons(static_cast<uint16_t>(payload_.size()));
    hdr.crc = htonl(crc_);

    // Копируем заголовок
    buffer.insert(buffer.end(), reinterpret_cast<const char*>(&hdr), 
                   reinterpret_cast<const char*>(&hdr) + sizeof(hdr));
    
    // Копируем данные
    buffer.insert(buffer.end(), payload_.begin(), payload_.end());

    return buffer;
}

Packet Packet::deserialize(const char* raw_header, const std::string& payload) {
    PacketHeader hdr;
    std::memcpy(&hdr, raw_header, sizeof(hdr));

    uint32_t id = ntohl(hdr.id);
    uint16_t len = ntohs(hdr.len);
    uint32_t crc = ntohl(hdr.crc);

    return Packet(id, len, crc, payload);
}

bool Packet::verify_crc() const {
    uint32_t expected = calculate_crc32(payload_.c_str(), payload_.size());
    return expected == crc_;
}

