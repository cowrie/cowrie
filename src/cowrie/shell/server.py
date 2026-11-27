# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import configparser
import json
import os
import random
from typing import TYPE_CHECKING

from twisted.logger import Logger

from cowrie.core.artifact import store_by_hash
from cowrie.core.config import CowrieConfig
from cowrie.core.resources import open_data_binary
from cowrie.shell import fs

if TYPE_CHECKING:
    from twisted.cred.portal import IRealm

    from cowrie.core.events import EventLog


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

    def logout(self, events: EventLog | None) -> None:
        """Store what the connection wrote, each file once with its final
        content, and report it on ``events``. Empty files are deleted."""
        if self.fs is None:
            return
        download_path = CowrieConfig.get("honeypot", "download_path", fallback=".")
        paths = self.fs.backing_file_paths()
        for realfile in self.fs.backing_files:
            try:
                if os.path.getsize(realfile) == 0:
                    os.remove(realfile)
                    continue
                shasum, stored, duplicate = store_by_hash(realfile, download_path)
            except FileNotFoundError:
                continue
            except OSError as e:
                self._log.error(
                    "Failed to store backing file {path}: {error!r}",
                    path=realfile,
                    error=e,
                )
                continue
            if events is not None:
                events.dispatch(
                    "cowrie.session.file_download",
                    "Saved redir contents with SHA-256 %(shasum)s to %(outfile)s",
                    duplicate=duplicate,
                    outfile=stored,
                    shasum=shasum,
                    destfile=paths.get(realfile, ""),
                )
        self.fs.backing_files.clear()

    def initFileSystem(self, home: str) -> None:
        """
        Create the emulated filesystem on first use. Not all connections need
        one. Every later channel and SFTP subsystem of the connection shares
        it, so a file written in one channel is there in the next.

        Channels of a connection are assumed to run one after another, as
        every multi-channel session seen in the wild does: each channel
        finds the files the previous one left. What the connection wrote is
        stored at logout.
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
