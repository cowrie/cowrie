# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import re
import time
import abc

from cowrie.core.config import CONFIG

# dblog now operates based on eventids, no longer on regex parsing of the entry.
# add an eventid using keyword args and it will be picked up by the dblogger

class DBLogger(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        self.sessions = {}
        self.ttylogs = {}
        # FIXME figure out what needs to be done here regarding
        #       HoneyPotTransport renamed to HoneyPotSSHTransport
        #:* Handles ipv6
        self.re_sessionlog = re.compile(
            r'.*HoneyPotSSHTransport,([0-9]+),[:a-f0-9.]+$')

        # cowrie.session.connect is special since it kicks off new logging session,
        # and is not handled here
        self.events = {
            'cowrie.login.success': self.handleLoginSucceeded,
            'cowrie.login.failed': self.handleLoginFailed,
            'cowrie.log.open': self.handleTTYLogOpened,
            'cowrie.command.success': self.handleCommand,
            'cowrie.command.failed': self.handleUnknownCommand,
            'cowrie.session.file_download': self.handleFileDownload,
            'cowrie.command.input': self.handleInput,
            'cowrie.client.version': self.handleClientVersion,
            'cowrie.client.size': self.handleTerminalSize,
            'cowrie.session.closed': self._connectionLost,
            'cowrie.log.closed': self.handleTTYLogClosed,
        }

        self.reported_ssh_port = None
        if CONFIG.has_option('honeypot', 'reported_ssh_port'):
            self.reported_ssh_port = CONFIG.getint('honeypot', 'reported_ssh_port')

        self.report_public_ip = False
        if CONFIG.has_option('honeypot', 'report_public_ip'):
            if CONFIG.getboolean('honeypot', 'report_public_ip') == True:
                self.report_public_ip = True
                import urllib
                self.public_ip = urllib.urlopen('http://myip.threatstream.com').readline()

        self.start()

    # used when the HoneypotTransport prefix is not available.
    def logDispatch(self, *msg, **kw):
        ev = kw
        ev['message'] = msg
        self.emit(ev)

    def start(self):
        """Hook that can be used to set up connections in dbloggers"""
        pass

    def getSensor(self):
        if CONFIG.has_option('honeypot', 'sensor_name'):
            return CONFIG.get('honeypot', 'sensor_name')
        return None

    def nowUnix(self):
        """return the current UTC time as an UNIX timestamp"""
        return int(time.time())

    def emit(self, ev):
        # ignore stdout and stderr
        if 'printed' in ev:
            return

        # ignore anything without eventid
        if not 'eventid' in ev:
            return

        # connection event is special. adds to list
        if ev['eventid'] == 'cowrie.session.connect':
            sessionno = ev['sessionno']
            peerIP, peerPort = ev['src_ip'], ev['src_port']
            hostIP, hostPort = ev['dst_ip'], ev['dst_port']

            if self.reported_ssh_port:
                hostPort = self.reported_ssh_port
            if self.report_public_ip:
                hostIP = self.public_ip

            self.sessions[sessionno] = \
                self.createSession(
                    peerIP, peerPort, hostIP, hostPort)
            return

        # use explicit sessionno if coming from dispatch
        if 'sessionno' in ev:
            sessionno = ev['sessionno']
            del ev['sessionno']
        # else extract session id from the twisted log prefix
        elif 'system' in ev:
            match = self.re_sessionlog.match(ev['system'])
            if not match:
                return
            sessionno = int(match.groups()[0])

        if sessionno not in self.sessions.keys():
            return

        if 'eventid' in ev:
            if ev['eventid'] in self.events:
                self.events[ev['eventid']](self.sessions[sessionno], ev)
                return

        pass

    def _connectionLost(self, session, args):
        self.handleConnectionLost(session, args)
        if session in self.ttylogs:
            del self.ttylogs[session]
        for i in [x for x in self.sessions if self.sessions[x] == session]:
            del self.sessions[i]

    def ttylog(self, session):
        ttylog = None
        if session in self.ttylogs:
            f = file(self.ttylogs[session])
            ttylog = f.read(10485760)
            f.close()
        return ttylog

    # We have to return a unique ID
    @abc.abstractmethod
    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        return 0

    # args has: ttylog
    def handleTTYLogOpened(self, session, args):
        self.ttylogs[session] = args['ttylog']

    # args has: ttylog
    def handleTTYLogClosed(self, session, args):
        self.ttylogs[session] = args['ttylog']

    # args is empty
    def handleConnectionLost(self, session, args):
        pass

    # args has: username, password
    def handleLoginFailed(self, session, args):
        pass

    # args has: username, password
    def handleLoginSucceeded(self, session, args):
        pass

    # args has: input
    def handleCommand(self, session, args):
        pass

    # args has: input
    def handleUnknownCommand(self, session, args):
        pass

    # args has: realm, input
    def handleInput(self, session, args):
        pass

    # args has: width, height
    def handleTerminalSize(self, session, args):
        pass

    # args has: version
    def handleClientVersion(self, session, args):
        pass

    # args has: url, outfile
    def handleFileDownload(self, session, args):
        pass

