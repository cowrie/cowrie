import struct


def string_to_hex(message):
    b = message.encode('utf-8')
    size = struct.pack('>L', len(b))
    return size + b


def bin_string_to_hex(message):
    size = struct.pack('>L', len(message))
    return size + message


def int_to_hex(value):
    return struct.pack('>L', value)
