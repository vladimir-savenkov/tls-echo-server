#!/usr/bin/env bash
# Собирает и запускает libFuzzer-цель парсера пакетов (fuzz/fuzz_packet.cpp).
# Использование: fuzz_packet.sh [max_total_time=60]
# Найденные падения (crash-*) сохраняются в build/fuzz/.
set -euo pipefail

max_time="${1:-60}"
cxx="${CXX:-clang++}"

mkdir -p build/fuzz/corpus

# Сидовый корпус: golden-кадры и граничные случаи в духе tests/test_packet.cpp,
# чтобы фаззер стартовал рядом с интересными путями.
python3 - <<'EOF'
import os
import struct
import zlib

os.makedirs("build/fuzz/corpus", exist_ok=True)

def frame(magic=b"TE", version=1, flags=0, packet_id=100, payload=b"hello",
          crc=None, length=None):
    if length is None:
        length = len(payload)
    if crc is None:
        crc = zlib.crc32(payload)
    return struct.pack(">2sBBIHI", magic, version, flags, packet_id, length,
                       crc) + payload

seeds = {
    "valid": frame(),
    "error_notification": frame(flags=1, packet_id=1, payload=b""),
    "empty_payload": frame(packet_id=42, payload=b""),
    "wrong_crc": frame(crc=zlib.crc32(b"hello") ^ 1),
    "bad_magic": frame(magic=b"XX"),
    "bad_version": frame(version=2),
    "len_mismatch": frame(payload=b"abc", length=10),
}
for name, data in seeds.items():
    with open(f"build/fuzz/corpus/{name}", "wb") as f:
        f.write(data)
EOF

"$cxx" -std=c++17 -g -O1 \
  -fsanitize=fuzzer,address -fno-omit-frame-pointer \
  -I include \
  src/protocol.cpp fuzz/fuzz_packet.cpp \
  -o build/fuzz/fuzz_packet

ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
  build/fuzz/fuzz_packet \
  -max_total_time="$max_time" \
  -use_value_profile=1 \
  -artifact_prefix=build/fuzz/ \
  -print_final_stats=1 \
  build/fuzz/corpus
