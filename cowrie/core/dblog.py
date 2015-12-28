# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import re
import time
import abc

# dblog now operates based on eventids, no longer on regex parsing of the entry.
# add an eventid using keyword args and it will be picked up by the dblogger
# the COWxxxx naming convention is still subject to change.

# COW0001 : create session
# COW0002 : succesful login
# COW0003 : failed login
# COW0004 : TTY log opened
# COW0005 : handle command
# COW0006 : handle unknown command
# COW0007 : file download
# COW0008 : INPUT
# COW0009 : SSH Version
# COW0010 : Terminal Size
# COW0011 : Connection Lost
# COW0012 : TTY log closed
# COW0013 : env var requested

class DBLogger(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions = {}
        self.ttylogs = {}
        self.re_sessionlog = re.compile(
            '.*HoneyPotTransport,([0-9]+),[0-9.]+$')

        # COW0001 is special since it kicks off new logging session,
        # and is not handled here
        self.events = {
            'COW0002': self.handleLoginSucceeded,
            'COW0003': self.handleLoginFailed,
            'COW0004': self.handleTTYLogOpened,
            'COW0005': self.handleCommand,
            'COW0006': self.handleUnknownCommand,
            'COW0007': self.handleFileDownload,
            'COW0008': self.handleInput,
            'COW0009': self.handleClientVersion,
            'COW0010': self.handleTerminalSize,
            'COW0011': self._connectionLost,
            'COW0012': self.handleTTYLogClosed,
        }

        self.reported_ssh_port = None
        if self.cfg.has_option('honeypot', 'reported_ssh_port'):
            self.reported_ssh_port = int(cfg.get('honeypot', 'reported_ssh_port'))

        self.report_public_ip = False
        if self.cfg.has_option('honeypot', 'report_public_ip'):
            if cfg.get('honeypot', 'report_public_ip') == "true" or cfg.get('honeypot', 'report_public_ip') == "1":
                self.report_public_ip = True
                import urllib
                self.public_ip = urllib.urlopen('http://myip.threatstream.com').readline()

        self.start(cfg)

    # used when the HoneypotTransport prefix is not available.
    def logDispatch(self, *msg, **kw):
        ev = kw
        ev['message'] = msg
        self.emit(ev)

    def start(self, cfg):
        """Hook that can be used to set up connections in dbloggers"""
        pass

    def getSensor(self):
        if self.cfg.has_option('honeypot', 'sensor_name'):
            return self.cfg.get('honeypot', 'sensor_name')
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
        if ev['eventid'] == 'COW0001':
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

