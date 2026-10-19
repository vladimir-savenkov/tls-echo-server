#!/usr/bin/env bash
set -euo pipefail

msan_prefix="${1:?usage: msan_packet_test.sh <instrumented-libcxx-prefix>}"
if [[ ! -f "$msan_prefix/lib/libc++.so" ]]; then
  echo "Instrumented libc++ not found in $msan_prefix" >&2
  exit 1
fi

mkdir -p build/msan
clang++-18 -std=c++17 -g -O1 \
  -fsanitize=memory -fsanitize-memory-track-origins=2 \
  -fno-omit-frame-pointer -fPIE -pie \
  -stdlib=libc++ -nostdinc++ \
  -isystem "$msan_prefix/include/c++/v1" -I include \
  src/protocol.cpp tests/test_packet.cpp \
  -L "$msan_prefix/lib" -Wl,-rpath,"$msan_prefix/lib" -lc++abi \
  -o build/msan/test_packet

MSAN_OPTIONS=halt_on_error=1:exit_code=86 build/msan/test_packet
