# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import os
import time
import hashlib

from twisted.python import log
from twisted.conch.insults import insults

from cowrie.core import ttylog
from cowrie.shell import protocol

from cowrie.core.config import CONFIG


class LoggingServerProtocol(insults.ServerProtocol):
    """
    Wrapper for ServerProtocol that implements TTY logging
    """
    stdinlogOpen = False
    ttylogOpen = False
    redirlogOpen = False  # it will be set at core/protocol.py

    def __init__(self, prot=None, *a, **kw):
        insults.ServerProtocol.__init__(self, prot, *a, **kw)
        self.bytesReceived = 0

        self.ttylogPath = CONFIG.get('honeypot', 'ttylog_path')
        self.downloadPath = CONFIG.get('honeypot', 'download_path')

        try:
            self.ttylogEnabled = CONFIG.getboolean('honeypot', 'ttylog')
        except:
            self.ttylogEnabled = True

        self.redirFiles = set()

        try:
            self.bytesReceivedLimit = CONFIG.getint('honeypot',
                'download_limit_size')
        except:
            self.bytesReceivedLimit = 0

        if prot is protocol.HoneyPotExecProtocol:
            self.type = 'e' # Execcmd
        else:
            self.type = 'i' # Interactive


    def getSessionId(self):
        """
        """
        transportId = self.transport.session.conn.transport.transportId
        channelId = self.transport.session.id
        return (transportId, channelId)


    def connectionMade(self):
        """
        """
        transportId, channelId = self.getSessionId()
        self.startTime = time.time()

        if self.ttylogEnabled:
            self.ttylogFile = '%s/%s-%s-%s%s.log' % \
                (self.ttylogPath, time.strftime('%Y%m%d-%H%M%S'),
                transportId, channelId, self.type)
            ttylog.ttylog_open(self.ttylogFile, self.startTime)
            self.ttylogOpen = True
            self.ttylogSize = 0
            log.msg(eventid='cowrie.log.open',
                ttylog=self.ttylogFile,
                format='Opening TTY Log: %(ttylog)s')

        self.stdinlogFile = '%s/%s-%s-%s-stdin.log' % \
            (self.downloadPath,
            time.strftime('%Y%m%d-%H%M%S'), transportId, channelId)

        if self.type == 'e':
            self.stdinlogOpen = True
        else: #i
            self.stdinlogOpen = False

        insults.ServerProtocol.connectionMade(self)


    def write(self, data):
        """
        Output sent back to user
        """
        if not isinstance(data, bytes):
            data = data.encode("utf-8")

        if self.ttylogEnabled and self.ttylogOpen:
            ttylog.ttylog_write(self.ttylogFile, len(data),
                ttylog.TYPE_OUTPUT, time.time(), data)
            self.ttylogSize += len(data)

        insults.ServerProtocol.write(self, data)


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

        if self.stdinlogOpen:
            with open(self.stdinlogFile, 'ab') as f:
                f.write(data)
        elif self.ttylogEnabled and self.ttylogOpen:
            ttylog.ttylog_write(self.ttylogFile, len(data),
                ttylog.TYPE_INPUT, time.time(), data)

        # prevent crash if something like this was passed:
        # echo cmd ; exit; \n\n
        if self.terminalProtocol:
            insults.ServerProtocol.dataReceived(self, data)


    def eofReceived(self):
        """
        Receive channel close and pass on to terminal
        """
        if self.terminalProtocol:
            self.terminalProtocol.eofReceived()


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
        if self.stdinlogOpen:
            try:
                with open(self.stdinlogFile, 'rb') as f:
                    shasum = hashlib.sha256(f.read()).hexdigest()
                    shasumfile = os.path.join(self.downloadPath, shasum)
                    if os.path.exists(shasumfile):
                        os.remove(self.stdinlogFile)
                        log.msg("Not storing duplicate content " + shasum)
                    else:
                        os.rename(self.stdinlogFile, shasumfile)
                    # os.symlink(shasum, self.stdinlogFile)
                log.msg(eventid='cowrie.session.file_download',
                        format='Saved stdin contents with SHA-256 %(shasum)s to %(outfile)s',
                        url='stdin',
                        outfile=shasumfile,
                        shasum=shasum,
                        destfile='')
            except IOError as e:
                pass
            finally:
                self.stdinlogOpen = False

        if self.redirFiles:
            for rp in self.redirFiles:

                rf = rp[0]

                if rp[1]:
                    url = rp[1]
                else:
                    url = rf[rf.find('redir_')+len('redir_'):]

                try:
                    if not os.path.exists(rf):
                        continue

                    if os.path.getsize(rf) == 0:
                        os.remove(rf)
                        continue

                    with open(rf, 'rb') as f:
                        shasum = hashlib.sha256(f.read()).hexdigest()
                        shasumfile = os.path.join(self.downloadPath, shasum)
                        if os.path.exists(shasumfile):
                            os.remove(rf)
                            log.msg("Not storing duplicate content " + shasum)
                        else:
                            os.rename(rf, shasumfile)
                        # os.symlink(shasum, rf)
                    log.msg(eventid='cowrie.session.file_download',
                            format='Saved redir contents with SHA-256 %(shasum)s to %(outfile)s',
                            url=url,
                            outfile=shasumfile,
                            shasum=shasum,
                            destfile=url)
                except IOError:
                    pass
            self.redirFiles.clear()

        if self.ttylogEnabled and self.ttylogOpen:
            log.msg(eventid='cowrie.log.closed',
                    format='Closing TTY Log: %(ttylog)s after %(duration)d seconds',
                    ttylog=self.ttylogFile,
                    size=self.ttylogSize,
                    duration=time.time()-self.startTime)
            ttylog.ttylog_close(self.ttylogFile, time.time())
            self.ttylogOpen = False

        insults.ServerProtocol.connectionLost(self, reason)



class LoggingTelnetServerProtocol(LoggingServerProtocol):
    """
    Wrap LoggingServerProtocol with single method to fetch session id for Telnet
    """

    def getSessionId(self):
        transportId = self.transport.session.transportId
        sn = self.transport.session.transport.transport.sessionno
        return (transportId, sn)
