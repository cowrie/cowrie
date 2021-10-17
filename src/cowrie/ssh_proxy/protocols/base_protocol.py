# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from __future__ import annotations


class BaseProtocol:
    data: bytes = b""
    packetSize: int = 0
    name: str = ""
    uuid: str = ""
    ttylog_file = None

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
