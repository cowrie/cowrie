# Copyright (c) 2017 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains a subclass of SSHChannel with additional logging
and session size limiting
"""

from __future__ import division, absolute_import

import os

from zope.interface import implementer

from twisted.python import log
from twisted.conch.ssh import channel

from cowrie.core import ttylog


class CowrieSSHChannel(ssh.SSHChannel):
    """
    This is an SSH channel with built-in logging
    """
    ttylogEnabled = True
    bytesReceived = 0
    bytesReceivedLimit = 0

    def __init__(self, *args, **kw):
        """
        Initialize logging
        """
        self.ttylogPath = cfg.get('honeypot', 'log_path')
        self.downloadPath = cfg.get('honeypot', 'download_path')
        try:
            self.ttylogEnabled = cfg.getboolean('honeypot', 'ttylog')
        except:
            self.ttylogEnabled = True

        try:
            self.bytesReceivedLimit = cfg.getint('honeypot',
                'download_limit_size')
        except:
            self.bytesReceivedLimit = 0

        channel.SSHChannel.__init__(self, localWindow, localMaxPacket,
          remoteWindow, remoteMaxPacket, conn, data, avatar)


    def dataReceived(self, data):
        """
        Called when we receive data from the user

        @type data: L{bytes}
        @param data: Data sent to the server from the client
        """
        self.bytesReceived += len(data)
        if self.bytesReceivedLimit \
          and self.bytesReceived > self.bytesReceivedLimit:
            log.msg(format='Data upload limit reached')
            self.eofReceived()
            return

        if self.ttylogEnabled:
            ttylog.ttylog_write(self.ttylogFile, len(data),
                ttylog.TYPE_INPUT, time.time(), data)

        channel.SSHChannel.dataReceived(self, data)


    def write(self, data):
        """
        Called when we send data to the user

        @type data: L{bytes}
        @param data: Data sent to the client from the server
        """
        if self.ttylogEnabled:
            ttylog.ttylog_write(self.ttylogFile, len(bytes),
                ttylog.TYPE_OUTPUT, time.time(), bytes)
            self.ttylogSize += len(bytes)

        channel.SSHChannel.write(self, data)

