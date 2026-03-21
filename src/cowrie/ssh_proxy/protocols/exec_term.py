# Copyright (C) 2016 Thomas Nicholson <tnnich@googlemail.com>
# SPDX-FileCopyrightText: 2021-2023 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import os
import time

from twisted.python import log

from cowrie.core import ttylog
from cowrie.core.config import CowrieConfig
from cowrie.ssh_proxy.protocols import base_protocol


class ExecTerm(base_protocol.BaseProtocol):
    def __init__(self, uuid, channelName, ssh, channelId, command):
        super().__init__(uuid, channelName, ssh)

        try:
            log.msg(
                eventid="cowrie.command.input",
                input=command.decode("utf8"),
                format="CMD: %(input)s",
            )
        except UnicodeDecodeError:
            log.err(f"Unusual execcmd: {command!r}")

        self.transportId = ssh.server.transportId
        self.channelId = channelId

        self.startTime: float = time.time()
        self.ttylogPath: str = CowrieConfig.get("honeypot", "ttylog_path")
        self.ttylogEnabled: bool = CowrieConfig.getboolean(
            "honeypot", "ttylog", fallback=True
        )
        self.ttylogSize: int = 0

        if self.ttylogEnabled:
            self.ttylogFile = "{}/{}-{}-{}e.log".format(
                self.ttylogPath,
                time.strftime("%Y%m%d-%H%M%S"),
                self.transportId,
                self.channelId,
            )
            ttylog.ttylog_open(self.ttylogFile, self.startTime)

    def parse_packet(self, parent: str, data: bytes) -> None:
        if self.ttylogEnabled:
            ttylog.ttylog_write(
                self.ttylogFile, len(data), ttylog.TYPE_OUTPUT, time.time(), data
            )
            self.ttylogSize += len(data)

    def channel_closed(self):
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
