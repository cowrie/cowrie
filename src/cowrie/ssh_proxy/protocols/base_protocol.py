# SPDX-FileCopyrightText: 2016 Thomas Nicholson <tnnich@googlemail.com>
# SPDX-FileCopyrightText: 2021-2024 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations


class BaseProtocol:
    data: bytes = b""
    packetSize: int = 0
    name: str = ""
    uuid: str = ""
    ttylog_file: str | None = None

    def __init__(self, uuid=None, name=None, ssh=None):
        if uuid is not None:
            self.uuid = uuid

        if name is not None:
            self.name = name

        if ssh is not None:
            self.ssh = ssh

    def parse_packet(self, parent: str, data: bytes) -> None:
        # log.msg(parent + ' ' + repr(data))
        # log.msg(parent + ' ' + '\'\\x' + "\\x".join("{:02x}".format(ord(c)) for c in self.data) + '\'')
        pass

    def channel_closed(self):
        pass

    def extract_int(self, length: int) -> int:
        value = int.from_bytes(self.data[:length], byteorder="big")
        self.packetSize = self.packetSize - length
        self.data = self.data[length:]
        return value

    def put_int(self, number: int) -> bytes:
        return number.to_bytes(4, byteorder="big")

    def extract_string(self) -> bytes:
        """
        note: this actually returns bytes!
        """
        length: int = self.extract_int(4)
        value: bytes = self.data[:length]
        self.packetSize -= length
        self.data = self.data[length:]
        return value

    def extract_bool(self) -> bool:
        value = self.extract_int(1)
        return bool(value)

    def extract_data(self) -> bytes:
        length = self.extract_int(4)
        self.packetSize = length
        value = self.data
        self.packetSize -= len(value)
        self.data = b""
        return value

    def __deepcopy__(self, memo):
        return None
