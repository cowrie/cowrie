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
        cfg = a[0].cfg
        self.bytesReceived = 0
        self.interactors = []

        self.ttylogPath = cfg.get('honeypot', 'log_path')
        self.downloadPath = cfg.get('honeypot', 'download_path')

        try:
            self.bytesReceivedLimit = int(cfg.get('honeypot',
                'download_limit_size'))
        except:
            self.bytesReceivedLimit = 0

        if prot is protocol.HoneyPotExecProtocol:
            self.type = 'e' # Execcmd
        else:
            self.type = 'i' # Interactive


    def connectionMade(self):
        """
        """
        transportId = self.transport.session.conn.transport.transportId
        channelId = self.transport.session.id

        self.startTime = time.time()
        self.ttylogFile = '%s/tty/%s-%s-%s%s.log' % \
            (self.ttylogPath, time.strftime('%Y%m%d-%H%M%S'),
            transportId, channelId, self.type)
        ttylog.ttylog_open(self.ttylogFile, self.startTime)
        self.ttylog_open = True
        self.ttylogSize = 0

        log.msg(eventid='cowrie.log.open',
                ttylog=self.ttylogFile,
                format='Opening TTY Log: %(ttylog)s')

        self.stdinlogFile = '%s/%s-%s-%s-stdin.log' % \
            (self.downloadPath,
            time.strftime('%Y%m%d-%H%M%S'), transportId, channelId)
        self.stdinlog_open = False

        insults.ServerProtocol.connectionMade(self)


    def write(self, bytes):
        """
        Output sent back to user
        """
        for i in self.interactors:
            i.sessionWrite(bytes)

        if self.ttylog_open:
            ttylog.ttylog_write(self.ttylogFile, len(bytes),
                ttylog.TYPE_OUTPUT, time.time(), bytes)
            self.ttylogSize += len(bytes)

        insults.ServerProtocol.write(self, bytes)


    def dataReceived(self, data):
        """
        Input received from user
        """
        self.bytesReceived += len(data)
        if self.bytesReceivedLimit \
          and self.bytesReceived > self.bytesReceivedLimit:
            log.msg(format='Data upload limit reached')
            #self.loseConnection()
            self.eofReceived()
            return

        if self.stdinlog_open:
            with open(self.stdinlogFile, 'ab') as f:
                f.write(data)
        elif self.ttylog_open:
            ttylog.ttylog_write(self.ttylogFile, len(data),
                ttylog.TYPE_INPUT, time.time(), data)

        insults.ServerProtocol.dataReceived(self, data)


    def eofReceived(self):
        """
        Receive channel close and pass on to terminal
        """
        if self.terminalProtocol:
            self.terminalProtocol.eofReceived()


    def addInteractor(self, interactor):
        """
        Add to list of interactors
        """
        self.interactors.append(interactor)


    def delInteractor(self, interactor):
        """
        Remove from list of interactors
        """
        self.interactors.remove(interactor)


    def loseConnection(self):
        """
        Override super to remove the terminal reset on logout
        """
        self.transport.loseConnection()


    def connectionLost(self, reason):
        """
        FIXME: this method is called 4 times on logout....
        it's called once from Avatar.closed() if disconnected
        """
        for i in self.interactors:
            i.sessionClosed()

        if self.stdinlog_open:
            try:
                with open(self.stdinlogFile, 'rb') as f:
                    shasum = hashlib.sha256(f.read()).hexdigest()
                    shasumfile = self.downloadPath + "/" + shasum
                    if (os.path.exists(shasumfile)):
                        os.remove(self.stdinlogFile)
                    else:
                        os.rename(self.stdinlogFile, shasumfile)
                    os.symlink(shasum, self.stdinlogFile)
                log.msg(eventid='cowrie.session.file_download',
                        format='Saved stdin contents to %(outfile)s',
                        url='stdin',
                        outfile=shasumfile,
                        shasum=shasum)
            except IOError as e:
                pass
            finally:
                self.stdinlog_open = False

        if self.ttylog_open:
            # TODO: Add session duration to this entry
            log.msg(eventid='cowrie.log.closed',
                    format='Closing TTY Log: %(ttylog)s after %(duration)d seconds',
                    ttylog=self.ttylogFile,
                    size=self.ttylogSize,
                    duration=time.time()-self.startTime)
            ttylog.ttylog_close(self.ttylogFile, time.time())
            self.ttylog_open = False

        insults.ServerProtocol.connectionLost(self, reason)

