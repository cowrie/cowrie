# Copyright (c) 2017 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains a subclass of SSHChannel with additional logging
and session size limiting
"""

from __future__ import annotations


import time

from twisted.conch.ssh import channel
from twisted.python import log

from cowrie.core import ttylog
from cowrie.core.config import CowrieConfig


class CowrieSSHChannel(channel.SSHChannel):
    """
    This is an SSH channel with built-in logging
    """

    ttylogFile: str = ""
    bytesReceived: int = 0
    bytesWritten: int = 0
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
        self.ttylogFile = "{}/tty/{}-{}-{}.log".format(
            self.ttylogPath,
            time.strftime("%Y%m%d-%H%M%S"),
            self.conn.transport.transportId,
            self.id,
        )
        log.msg(
            eventid="cowrie.log.open",
            ttylog=self.ttylogFile,
            format="Opening TTY Log: %(ttylog)s",
        )
        ttylog.ttylog_open(self.ttylogFile, time.time())
        channel.SSHChannel.channelOpen(self, specificData)

    def closed(self) -> None:
        log.msg(
            eventid="cowrie.log.closed",
            format="Closing TTY Log: %(ttylog)s after %(duration)s seconds",
            ttylog=self.ttylogFile,
            size=self.bytesReceived + self.bytesWritten,
            duration=f"{time.time() - self.startTime:.1f}",
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
            log.msg(f"Data upload limit reached for channel {self.id}")
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
