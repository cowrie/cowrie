# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import configparser
import json
import random
from typing import TYPE_CHECKING

from twisted.logger import Logger

from cowrie.core.config import CowrieConfig
from cowrie.core.resources import open_data_binary
from cowrie.shell import fs

if TYPE_CHECKING:
    from twisted.cred.portal import IRealm


class CowrieServer:
    """
    The emulated machine of one connection. Every channel and SFTP
    subsystem of the connection shares its filesystem.
    """

    _log = Logger()

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

        self._log.info(
            "Initialized emulated server as architecture: {arch}", arch=self.arch
        )

    def logout(self) -> None:
        """Release what the connection held on the real disk."""
        if self.fs is not None:
            self.fs.remove_backing_files()

    def initFileSystem(self, home: str) -> None:
        """
        Create the emulated filesystem on first use. Not all connections need
        one. Every later channel and SFTP subsystem of the connection shares
        it, so a file written in one channel is there in the next.

        Channels of a connection are assumed to run one after another, as
        every multi-channel session seen in the wild does: each channel
        finds the files the previous one left, and stores what it wrote
        when it closes.
        """
        if self.fs is not None:
            return
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
            self._log.info("Could not load process list {error!r}", error=e)
            self.process = None
