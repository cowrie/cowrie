# SPDX-FileCopyrightText: 2017-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
This module contains a subclass of SSHChannel with additional logging
and session size limiting
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from twisted.conch.ssh import channel
from twisted.logger import Logger

from cowrie.core import ttylog
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from cowrie.core.events import EventLog


class CowrieSSHChannel(channel.SSHChannel):
    """
    This is an SSH channel with built-in logging

    Not wired into the SSH service: the session channel is
    HoneyPotSSHSession and the forwarding channels subclass conch's
    forwarding channel, so no production code instantiates this class;
    only tests do. Its ttylog duplicates what
    insults.LoggingServerProtocol records.
    """

    _log = Logger()
    ttylogFile: str = ""
    bytesReceived: int = 0
    bytesWritten: int = 0
    # The session's event emitter, bound from the transport in channelOpen.
    events: EventLog
    name: bytes = b"cowrie-ssh-channel"
    startTime: float = 0.0
    ttylogPath: str = CowrieConfig.get("honeypot", "log_path", fallback=".")
    downloadPath: str = CowrieConfig.get("honeypot", "download_path", fallback=".")
    ttylogEnabled: bool = CowrieConfig.getboolean("honeypot", "ttylog", fallback=True)
    bytesReceivedLimit: int = CowrieConfig.getint(
        "honeypot", "download_limit_size", fallback=0
    )

    def __repr__(self) -> str:
        """
        Return a pretty representation of this object.

        @return Pretty representation of this object as a string
        @rtype: L{str}
        """
        return f"Cowrie SSH Channel {self.name.decode()}"

    def __init__(self, *args, **kw):
        """
        Initialize logging
        """
        channel.SSHChannel.__init__(self, *args, **kw)

    def channelOpen(self, specificData: bytes) -> None:
        self.startTime = time.time()
        self.events = self.conn.transport.events
        self.ttylogFile = "{}/tty/{}-{}-{}.log".format(
            self.ttylogPath,
            time.strftime("%Y%m%d-%H%M%S"),
            self.conn.transport.transportId,
            self.id,
        )
        self.events.dispatch(
            "cowrie.log.open",
            "Opening TTY Log: %(ttylog)s",
            ttylog=self.ttylogFile,
        )
        ttylog.ttylog_open(self.ttylogFile, time.time())
        channel.SSHChannel.channelOpen(self, specificData)

    def closed(self) -> None:
        self.events.dispatch(
            "cowrie.log.closed",
            "Closing TTY Log: %(ttylog)s after %(duration_ms)d milliseconds",
            ttylog=self.ttylogFile,
            size=self.bytesReceived + self.bytesWritten,
            duration_ms=round((time.time() - self.startTime) * 1000),
        )
        ttylog.ttylog_close(self.ttylogFile, time.time())
        channel.SSHChannel.closed(self)

    def dataReceived(self, data: bytes) -> None:
        """
        Called when we receive data from the user

        @type data: L{bytes}
        @param data: Data sent to the server from the client
        """
        self.bytesReceived += len(data)
        if self.bytesReceivedLimit and self.bytesReceived > self.bytesReceivedLimit:
            self._log.info(
                "Data upload limit reached for channel {channel_id}",
                channel_id=self.id,
            )
            self.eofReceived()
            return

        if self.ttylogEnabled:
            ttylog.ttylog_write(
                self.ttylogFile, len(data), ttylog.TYPE_INPUT, time.time(), data
            )

        channel.SSHChannel.dataReceived(self, data)

    def write(self, data: bytes) -> None:
        """
        Called when we send data to the user

        @type data: L{bytes}
        @param data: Data sent to the client from the server
        """
        if self.ttylogEnabled:
            ttylog.ttylog_write(
                self.ttylogFile, len(data), ttylog.TYPE_OUTPUT, time.time(), data
            )
            self.bytesWritten += len(data)

        channel.SSHChannel.write(self, data)
