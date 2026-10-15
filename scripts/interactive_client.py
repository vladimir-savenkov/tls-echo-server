#!/usr/bin/env python3
"""Interactive client for the binary TLS echo protocol."""

import argparse
import socket
import ssl
import struct
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
        raise ValueError(f"input exceeds {MAX_PAYLOAD} encoded bytes")
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


def receive_packet(connection: ssl.SSLSocket) -> tuple[int, bytes, int]:
    packet_id, size, expected_crc = HEADER.unpack(
        receive_exact(connection, HEADER.size)
    )
    payload = receive_exact(connection, size)
    actual_crc = zlib.crc32(payload) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise ValueError(
            f"CRC mismatch: expected {expected_crc:#010x}, got {actual_crc:#010x}"
        )
    return packet_id, payload, actual_crc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interact with the TLS echo server.")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--ca-cert", help="CA or self-signed server certificate")
    parser.add_argument(
        "--insecure", action="store_true",
        help="disable certificate verification (local testing only)",
    )
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main() -> int:
    args = parse_args()
    context = make_context(args.ca_cert, args.insecure)
    try:
        with socket.create_connection(
            (args.host, args.port), timeout=args.timeout
        ) as tcp:
            with context.wrap_socket(tcp, server_hostname=args.host) as connection:
                connection.settimeout(args.timeout)
                print(f"connected to {args.host}:{args.port}")
                print("Enter text. Use /quit, /exit, Ctrl-C, or Ctrl-D to exit.")
                packet_id = 1
                while True:
                    try:
                        text = input("> ")
                    except (EOFError, KeyboardInterrupt):
                        print()
                        break
                    if text.strip().lower() in {"/quit", "/exit"}:
                        break

                    payload = text.encode("utf-8")
                    connection.sendall(encode_packet(packet_id, payload))
                    response_id, response, crc = receive_packet(connection)
                    if response_id != packet_id:
                        raise ValueError(
                            f"expected response id {packet_id}, got {response_id}"
                        )
                    print(
                        f"reply id={response_id} bytes={len(response)} "
                        f"crc={crc:#010x}: "
                        f"{response.decode('utf-8', errors='replace')}"
                    )
                    packet_id = (packet_id + 1) & 0xFFFFFFFF
    except (ConnectionError, OSError, ssl.SSLError, ValueError) as error:
        print(f"error: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
