# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import os
import time
import hashlib

from twisted.python import log
from twisted.conch.insults import insults

from cowrie.core import ttylog
from cowrie.core import protocol


class LoggingServerProtocol(insults.ServerProtocol):
    """
    Wrapper for ServerProtocol that implements TTY logging
    """

    def __init__(self, prot=None, *a, **kw):
        insults.ServerProtocol.__init__(self, prot, *a, **kw)
        self.cfg = a[0].cfg
        self.bytesReceived = 0
        self.interactors = []

        try:
            self.bytesReceivedLimit = int(self.cfg.get('honeypot', 'download_limit_size'))
        except:
            self.bytesReceivedLimit = 0

        if prot is protocol.HoneyPotExecProtocol:
            self.type = 'e' # execcmd
        else:
            self.type = 'i' # interactive


    def connectionMade(self):
        """
        """
        transportId = self.transport.session.conn.transport.transportId
        channelId = self.transport.session.id

        self.ttylog_file = '%s/tty/%s-%s-%s%s.log' % \
            (self.cfg.get('honeypot', 'log_path'),
            time.strftime('%Y%m%d-%H%M%S'), transportId, channelId,
            self.type)
        ttylog.ttylog_open(self.ttylog_file, time.time())
        self.ttylog_open = True

        log.msg(eventid='COW0004', ttylog=self.ttylog_file,
            format='Opening TTY Log: %(ttylog)s')

        self.stdinlog_file = '%s/%s-%s-%s-stdin.log' % \
            (self.cfg.get('honeypot', 'download_path'),
            time.strftime('%Y%m%d-%H%M%S'), transportId, channelId)
        self.stdinlog_open = False

        insults.ServerProtocol.connectionMade(self)


    def write(self, bytes):
        """
        """
        for i in self.interactors:
            i.sessionWrite(bytes)

        if self.ttylog_open:
            ttylog.ttylog_write(self.ttylog_file, len(bytes),
                ttylog.TYPE_OUTPUT, time.time(), bytes)

        insults.ServerProtocol.write(self, bytes)


    def dataReceived(self, data):
        """
        """
        self.bytesReceived += len(data)
        if self.bytesReceivedLimit and self.bytesReceived > self.bytesReceivedLimit:
            log.msg(eventid='COW0015', format='Data upload limit reached')
            #self.loseConnection()
            self.eofReceived()
            return

        if self.stdinlog_open:
            with file(self.stdinlog_file, 'ab') as f:
                f.write(data)
        elif self.ttylog_open:
            ttylog.ttylog_write(self.ttylog_file, len(data),
                ttylog.TYPE_INPUT, time.time(), data)

        insults.ServerProtocol.dataReceived(self, data)


    def eofReceived(self):
        """
        """
        if self.terminalProtocol:
            self.terminalProtocol.eofReceived()


    def addInteractor(self, interactor):
        """
        """
        self.interactors.append(interactor)


    def delInteractor(self, interactor):
        """
        """
        self.interactors.remove(interactor)


    def loseConnection(self):
        """
        override super to remove the terminal reset on logout

        """
        self.transport.loseConnection()


    def connectionLost(self, reason):
        """
        FIXME: this method is called 4 times on logout....
        it's called once from Avatar.closed() if disconnected
        """
        log.msg("received call to LSP.connectionLost")

        for i in self.interactors:
            i.sessionClosed()

        transport = self.transport.session.conn.transport

        if self.stdinlog_open:
            try:
                with open(self.stdinlog_file, 'rb') as f:
                    shasum = hashlib.sha256(f.read()).hexdigest()
                    shasumfile = self.cfg.get('honeypot',
                        'download_path') + "/" + shasum
                    if (os.path.exists(shasumfile)):
                        os.remove(self.stdinlog_file)
                    else:
                        os.rename(self.stdinlog_file, shasumfile)
                    os.symlink(shasum, self.stdinlog_file)
                log.msg(eventid='COW0007',
                    format='Saved stdin contents to %(outfile)s',
                    url='stdin', outfile=shasumfile, shasum=shasum)
            except IOError as e:
                pass
            finally:
                self.stdinlog_open = False

        if self.ttylog_open:
            log.msg(eventid='COW0012', format='Closing TTY Log: %(ttylog)s',
                ttylog=self.ttylog_file)
            ttylog.ttylog_close(self.ttylog_file, time.time())
            self.ttylog_open = False

        self.cfg = None
        insults.ServerProtocol.connectionLost(self, reason)

