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

import os
import time

from twisted.python import log

from cowrie.core import ttylog
from cowrie.core.config import CowrieConfig
from cowrie.ssh_proxy.protocols import base_protocol


class Term(base_protocol.BaseProtocol):
    def __init__(self, uuid, chan_name, ssh, channelId):
        super().__init__(uuid, chan_name, ssh)

        self.command: bytes = b""
        self.pointer: int = 0
        self.tabPress: bool = False
        self.upArrow: bool = False

        self.transportId: int = ssh.server.transportId
        self.channelId: int = channelId

        self.startTime: float = time.time()
        self.ttylogPath: str = CowrieConfig.get("honeypot", "ttylog_path")
        self.ttylogEnabled: bool = CowrieConfig.getboolean(
            "honeypot", "ttylog", fallback=True
        )
        self.ttylogSize: int = 0

        if self.ttylogEnabled:
            self.ttylogFile = "{}/{}-{}-{}i.log".format(
                self.ttylogPath, time.strftime("%Y%m%d-%H%M%S"), uuid, self.channelId
            )
            ttylog.ttylog_open(self.ttylogFile, self.startTime)

    def channel_closed(self) -> None:
        if self.ttylogEnabled:
            ttylog.ttylog_close(self.ttylogFile, time.time())
            shasum = ttylog.ttylog_inputhash(self.ttylogFile)
            shasumfile = os.path.join(self.ttylogPath, shasum)

            if os.path.exists(shasumfile):
                duplicate = True
                os.remove(self.ttylogFile)
            else:
                duplicate = False
                os.rename(self.ttylogFile, shasumfile)
                umask = os.umask(0)
                os.umask(umask)
                os.chmod(shasumfile, 0o666 & ~umask)

            log.msg(
                eventid="cowrie.log.closed",
                format="Closing TTY Log: %(ttylog)s after %(duration)d seconds",
                ttylog=shasumfile,
                size=self.ttylogSize,
                shasum=shasum,
                duplicate=duplicate,
                duration=time.time() - self.startTime,
            )

    def parse_packet(self, parent: str, data: bytes) -> None:
        self.data: bytes = data

        if parent == "[SERVER]":
            while len(self.data) > 0:
                # If Tab Pressed
                if self.data[:1] == b"\x09":
                    self.tabPress = True
                    self.data = self.data[1:]
                # If Backspace Pressed
                elif self.data[:1] == b"\x7f" or self.data[:1] == b"\x08":
                    if self.pointer > 0:
                        self.command = (
                            self.command[: self.pointer - 1]
                            + self.command[self.pointer :]
                        )
                        self.pointer -= 1
                    self.data = self.data[1:]
                # If enter or ctrl+c or newline
                elif (
                    self.data[:1] == b"\x0d"
                    or self.data[:1] == b"\x03"
                    or self.data[:1] == b"\x0a"
                ):
                    if self.data[:1] == b"\x03":
                        self.command += b"^C"

                    self.data = self.data[1:]

                    try:
                        if self.command != b"":
                            log.msg(
                                eventid="cowrie.command.input",
                                input=self.command.decode("utf8"),
                                format="CMD: %(input)s",
                            )
                    except UnicodeDecodeError:
                        log.err(f"Unusual execcmd: {self.command!r}")

                    self.command = b""
                    self.pointer = 0
                # If Home Pressed
                elif self.data[:3] == b"\x1b\x4f\x48":
                    self.pointer = 0
                    self.data = self.data[3:]
                # If End Pressed
                elif self.data[:3] == b"\x1b\x4f\x46":
                    self.pointer = len(self.command)
                    self.data = self.data[3:]
                # If Right Pressed
                elif self.data[:3] == b"\x1b\x5b\x43":
                    if self.pointer != len(self.command):
                        self.pointer += 1
                    self.data = self.data[3:]
                # If Left Pressed
                elif self.data[:3] == b"\x1b\x5b\x44":
                    if self.pointer != 0:
                        self.pointer -= 1
                    self.data = self.data[3:]
                # If up or down arrow
                elif (
                    self.data[:3] == b"\x1b\x5b\x41" or self.data[:3] == b"\x1b\x5b\x42"
                ):
                    self.upArrow = True
                    self.data = self.data[3:]
                else:
                    self.command = (
                        self.command[: self.pointer]
                        + self.data[:1]
                        + self.command[self.pointer :]
                    )
                    self.pointer += 1
                    self.data = self.data[1:]

            if self.ttylogEnabled:
                self.ttylogSize += len(data)
                ttylog.ttylog_write(
                    self.ttylogFile,
                    len(data),
                    ttylog.TYPE_OUTPUT,
                    time.time(),
                    data,
                )

        elif parent == "[CLIENT]":
            if self.tabPress:
                if not self.data.startswith(b"\x0d"):
                    if self.data != b"\x07":
                        self.command = self.command + self.data
                self.tabPress = False

            if self.upArrow:
                while len(self.data) != 0:
                    # Backspace
                    if self.data[:1] == b"\x08":
                        self.command = self.command[:-1]
                        self.pointer -= 1
                        self.data = self.data[1:]
                    # ESC[K - Clear Line
                    elif self.data[:3] == b"\x1b\x5b\x4b":
                        self.command = self.command[: self.pointer]
                        self.data = self.data[3:]
                    elif self.data[:1] == b"\x0d":
                        self.pointer = 0
                        self.data = self.data[1:]
                    # Right Arrow
                    elif self.data[:3] == b"\x1b\x5b\x43":
                        self.pointer += 1
                        self.data = self.data[3:]
                    elif self.data[:2] == b"\x1b\x5b" and self.data[3:3] == b"\x50":
                        self.data = self.data[4:]
                    # Needed?!
                    elif self.data[:1] != b"\x07" and self.data[:1] != b"\x0d":
                        self.command = (
                            self.command[: self.pointer]
                            + self.data[:1]
                            + self.command[self.pointer :]
                        )
                        self.pointer += 1
                        self.data = self.data[1:]
                    else:
                        self.pointer += 1
                        self.data = self.data[1:]

                self.upArrow = False

            if self.ttylogEnabled:
                self.ttylogSize += len(data)
                ttylog.ttylog_write(
                    self.ttylogFile,
                    len(data),
                    ttylog.TYPE_INPUT,
                    time.time(),
                    data,
                )
