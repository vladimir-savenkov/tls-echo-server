#!/usr/bin/env python3
"""Run concurrent TLS clients against the binary echo server."""

import argparse
import concurrent.futures
import socket
import ssl
import struct
import threading
import time
import zlib

HEADER = struct.Struct("!IHI")
MAX_PAYLOAD = 0xFFFF


def make_context(ca_cert: str | None, insecure: bool) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=ca_cert)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def encode_packet(packet_id: int, payload: bytes) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload exceeds {MAX_PAYLOAD} bytes")
    return HEADER.pack(
        packet_id, len(payload), zlib.crc32(payload) & 0xFFFFFFFF
    ) + payload


def receive_exact(connection: ssl.SSLSocket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise ConnectionError(
                f"connection closed after {len(result)} of {size} bytes"
            )
        result.extend(chunk)
    return bytes(result)


def receive_packet(connection: ssl.SSLSocket) -> tuple[int, bytes]:
    packet_id, size, expected_crc = HEADER.unpack(
        receive_exact(connection, HEADER.size)
    )
    payload = receive_exact(connection, size)
    actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise ValueError(
            f"CRC mismatch: expected {expected_crc:#010x}, got {actual_crc:#010x}"
        )
    return packet_id, payload


def run_client(
    number: int, args: argparse.Namespace, barrier: threading.Barrier
) -> tuple[int, float]:
    context = make_context(args.ca_cert, args.insecure)
    barrier.wait(timeout=args.timeout)
    started = time.monotonic()
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as tcp:
        with context.wrap_socket(tcp, server_hostname=args.host) as connection:
            connection.settimeout(args.timeout)
            for message_number in range(args.messages):
                packet_id = (number << 16) | message_number
                payload = (
                    f"{args.payload_prefix} client={number} message={message_number}"
                ).encode()
                connection.sendall(encode_packet(packet_id, payload))
                response_id, response = receive_packet(connection)
                if response_id != packet_id or response != payload:
                    raise ValueError(
                        f"client {number}: response does not match request {message_number}"
                    )
    return number, time.monotonic() - started


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Open concurrent TLS connections and verify echo responses."
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--clients", type=int, default=10)
    parser.add_argument("--messages", type=int, default=5)
    parser.add_argument("--payload-prefix", default="concurrency test")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--ca-cert", help="CA or self-signed server certificate")
    parser.add_argument(
        "--insecure", action="store_true",
        help="disable certificate verification (local testing only)",
    )
    args = parser.parse_args()
    if not 1 <= args.clients <= 0xFFFF:
        parser.error("--clients must be between 1 and 65535")
    if not 1 <= args.messages <= 0x10000:
        parser.error("--messages must be between 1 and 65536")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main() -> int:
    args = parse_args()
    barrier = threading.Barrier(args.clients)
    failures = 0
    completed = 0
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.clients) as executor:
        futures = [
            executor.submit(run_client, number, args, barrier)
            for number in range(args.clients)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                number, duration = future.result()
                completed += args.messages
                print(f"client {number}: {args.messages} replies in {duration:.3f}s")
            except Exception as error:  # Keep collecting results from other clients.
                failures += 1
                print(f"FAILED: {error}")

    duration = time.monotonic() - started
    print(
        f"completed {completed} messages across {args.clients} clients "
        f"in {duration:.3f}s; failures={failures}"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
