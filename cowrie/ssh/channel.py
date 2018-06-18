# Copyright (c) 2017 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains a subclass of SSHChannel with additional logging
and session size limiting
"""

from __future__ import division, absolute_import

import time

from twisted.python import log
from twisted.conch.ssh import channel

from cowrie.core import ttylog
from cowrie.core.config import CONFIG


class CowrieSSHChannel(channel.SSHChannel):
    """
    This is an SSH channel with built-in logging
    """
    ttylogEnabled = True
    ttylogFile = ""
    bytesReceived = 0
    bytesReceivedLimit = 0
    bytesWritten = 0
    name = b'cowrie-ssh-channel'
    startTime = None


    def __repr__(self):
        """
        Return a pretty representation of this object.

        @return Pretty representation of this object as a string
        @rtype: L{str}
        """
        return "Cowrie SSH Channel {}".format(self.name)


    def __init__(self, *args, **kw):
        """
        Initialize logging
        """
        self.ttylogPath = CONFIG.get('honeypot', 'log_path')
        self.downloadPath = CONFIG.get('honeypot', 'download_path')
        try:
            self.ttylogEnabled = CONFIG.getboolean('honeypot', 'ttylog')
        except:
            self.ttylogEnabled = True

        try:
            self.bytesReceivedLimit = CONFIG.getint('honeypot',
                'download_limit_size')
        except:
            self.bytesReceivedLimit = 0

        channel.SSHChannel.__init__(self, *args, **kw)


    def channelOpen(self, specificData):
        """
        """
        self.startTime = time.time()
        self.ttylogFile = '%s/tty/%s-%s-%s.log' % \
            (self.ttylogPath, time.strftime('%Y%m%d-%H%M%S'),
            self.conn.transport.transportId, self.id)
        log.msg(eventid='cowrie.log.open',
            ttylog=self.ttylogFile,
            format="Opening TTY Log: %(ttylog)s")
        ttylog.ttylog_open(self.ttylogFile, time.time())
        channel.SSHChannel.channelOpen(self, specificData)


    def closed(self):
        """
        """
        log.msg(eventid='cowrie.log.closed',
            format="Closing TTY Log: %(ttylog)s after %(duration)d seconds",
            ttylog=self.ttylogFile,
            size=self.bytesReceived+self.bytesWritten,
            duration=time.time()-self.startTime)
        ttylog.ttylog_close(self.ttylogFile, time.time())
        channel.SSHChannel.closed(self)


    def dataReceived(self, data):
        """
        Called when we receive data from the user

        @type data: L{bytes}
        @param data: Data sent to the server from the client
        """
        self.bytesReceived += len(data)
        if self.bytesReceivedLimit \
          and self.bytesReceived > self.bytesReceivedLimit:
            log.msg("Data upload limit reached for channel {}".format(self.id))
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
            ttylog.ttylog_write(self.ttylogFile, len(data),
                ttylog.TYPE_OUTPUT, time.time(), data)
            self.bytesWritten += len(data)

        channel.SSHChannel.write(self, data)
