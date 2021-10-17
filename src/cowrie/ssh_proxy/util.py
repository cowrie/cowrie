from __future__ import annotations
import struct


def string_to_hex(message: str) -> bytes:
    b = message.encode("utf-8")
    size = struct.pack(">L", len(b))
    return size + b


def bin_string_to_hex(message: bytes) -> bytes:
    size = struct.pack(">L", len(message))
    return size + message


def int_to_hex(value: int) -> bytes:
    return struct.pack(">L", value)
