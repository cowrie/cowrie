# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import configparser
import json
import random
from typing import TYPE_CHECKING

from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.core.resources import open_data_binary
from cowrie.shell import fs

if TYPE_CHECKING:
    from twisted.cred.portal import IRealm


class CowrieServer:
    """
    In traditional Kippo each connection gets its own simulated machine.
    This is not always ideal, sometimes two connections come from the same
    source IP address. we want to give them the same environment as well.
    So files uploaded through SFTP are visible in the SSH session.
    This class represents a 'virtual server' that can be shared between
    multiple Cowrie connections
    """

    def __init__(self, realm: IRealm) -> None:
        self.fs: fs.HoneyPotFilesystem | None = None
        self.process = None
        self.hostname: str = CowrieConfig.get("honeypot", "hostname", fallback="svr04")
        try:
            arches = [
                arch.strip()
                for arch in CowrieConfig.get(
                    "shell", "arch", fallback="linux-x64-lsb"
                ).split(",")
            ]
            self.arch = random.choice(arches)
        except configparser.Error:
            self.arch = "linux-x64-lsb"

        log.msg(f"Initialized emulated server as architecture: {self.arch}")

    def initFileSystem(self, home: str) -> None:
        """
        Do this so we can trigger it later. Not all sessions need file system
        """
        self.fs = fs.HoneyPotFilesystem(self.arch, home)

        processes = CowrieConfig.get("shell", "processes", fallback=None)
        try:
            if processes:
                with open(processes, encoding="utf-8") as f:
                    cmdoutput = json.load(f)
            else:
                with open_data_binary("cmdoutput.json") as f:
                    cmdoutput = json.load(f)
            self.process = cmdoutput["command"]["ps"]
        except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
            log.msg(f"Could not load process list {e!r}")
            self.process = None
