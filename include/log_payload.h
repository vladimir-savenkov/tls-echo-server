#pragma once

#include <string>
#include <string_view>

// Keep packet bytes on one readable log line, including binary payloads.
inline std::string escape_log_payload(std::string_view payload) {
    constexpr std::string_view hex = "0123456789ABCDEF";
    std::string escaped;
    escaped.reserve(payload.size());

    for (unsigned char byte : payload) {
        switch (byte) {
            case '\\': escaped += "\\\\"; break;
            case '"': escaped += "\\\""; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (byte >= 0x20 && byte <= 0x7e) {
                    escaped += static_cast<char>(byte);
                } else {
                    escaped += "\\x";
                    escaped += hex[byte >> 4];
                    escaped += hex[byte & 0x0f];
                }
        }
    }
    return escaped;
}
