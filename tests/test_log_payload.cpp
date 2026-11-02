#include "log_payload.h"

#include <iostream>
#include <string>

namespace {
int failures = 0;

void check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void test_printable_payload_passes_through() {
    check(escape_log_payload("") == "", "empty payload stays empty");
    check(escape_log_payload("Hello, world! 123") == "Hello, world! 123",
          "printable ASCII passes through unchanged");
}

void test_escapes_special_characters() {
    check(escape_log_payload("a\\b") == "a\\\\b", "backslash is escaped");
    check(escape_log_payload("say \"hi\"") == "say \\\"hi\\\"", "quote is escaped");
    check(escape_log_payload("line\nbreak") == "line\\nbreak", "newline is escaped");
    check(escape_log_payload("ret\rurn") == "ret\\rurn", "carriage return is escaped");
    check(escape_log_payload("tab\there") == "tab\\there", "tab is escaped");
}

void test_escapes_binary_bytes_as_hex() {
    const std::string binary{"\x00\x01\x7F\x80\xFF", 5};
    check(escape_log_payload(binary) == "\\x00\\x01\\x7F\\x80\\xFF",
          "control and high bytes become uppercase hex escapes");
    check(escape_log_payload(std::string("\xE9")) == "\\xE9",
          "non-ASCII byte becomes a hex escape");
}

void test_payload_stays_on_single_log_line() {
    const std::string escaped = escape_log_payload("junk\n\"quoted\"\r\n\x01\t\\");
    check(escaped.find('\n') == std::string::npos,
          "escaped payload contains no raw newline");
    check(escaped.find('\r') == std::string::npos,
          "escaped payload contains no raw carriage return");
    check(escaped == "junk\\n\\\"quoted\\\"\\r\\n\\x01\\t\\\\",
          "mixed payload is fully escaped");
}
}  // namespace

int main() {
    test_printable_payload_passes_through();
    test_escapes_special_characters();
    test_escapes_binary_bytes_as_hex();
    test_payload_stays_on_single_log_line();
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << "All log payload tests passed\n";
    return 0;
}
