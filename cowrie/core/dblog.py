# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import re
import time
import abc

# dblog now operates based on eventids, no longer on regex parsing of the entry.
# add an eventid using keyword args and it will be picked up by the dblogger
# the KIPPxxxx naming convention is still subject to change.

# KIPP0001 : create session
# KIPP0002 : succesful login
# KIPP0003 : failed login
# KIPP0004 : TTY log opened
# KIPP0005 : handle command
# KIPP0006 : handle unknown command
# KIPP0007 : file download
# KIPP0008 : INPUT
# KIPP0009 : SSH Version
# KIPP0010 : Terminal Size
# KIPP0011 : Connection Lost
# KIPP0012 : TTY log closed
# KIPP0013 : env var requested

class DBLogger(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions = {}
        self.ttylogs = {}
        self.re_sessionlog = re.compile(
            '.*HoneyPotTransport,([0-9]+),[0-9.]+$')

        # KIPP0001 is special since it kicks off new logging session,
        # and is not handled here
        self.events = {
            'KIPP0002': self.handleLoginSucceeded,
            'KIPP0003': self.handleLoginFailed,
            'KIPP0004': self.handleTTYLogOpened,
            'KIPP0005': self.handleCommand,
            'KIPP0006': self.handleUnknownCommand,
            'KIPP0007': self.handleFileDownload,
            'KIPP0008': self.handleInput,
            'KIPP0009': self.handleClientVersion,
            'KIPP0010': self.handleTerminalSize,
            'KIPP0011': self._connectionLost,
            'KIPP0012': self.handleTTYLogClosed,
        }

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
        return int(time.mktime(time.gmtime()[:-1] + (-1,)))

    def emit(self, ev):
        # ignore stdout and stderr
        if 'printed' in ev:
            return

        # ignore anything without eventid
        if not 'eventid' in ev:
            return

        # connection event is special. adds to list
        if ev['eventid'] == 'KIPP0001':
            sessionno = ev['sessionno']
            self.sessions[sessionno] = \
                self.createSession(
                    ev['src_ip'], ev['src_port'], ev['dst_ip'], ev['dst_port'])
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

# vim: set sw=4 et:
