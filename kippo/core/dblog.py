# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import re
import time
import abc

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

class DBLogger(object):

    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions = {}
        self.ttylogs = {}
        self.re_sessionlog = re.compile(
            '.*HoneyPotTransport,([0-9]+),[0-9.]+$')

        # KIPP0001 is special since it kicks off new logging event,
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
        }

        self.start(cfg)

    # use logDispatch when the HoneypotTransport prefix is not available.
    # here you can explicitly set the sessionIds to tie the sessions together
    def logDispatch(self, sessionid, msg):
        if isinstance( msg, dict ):
            msg['sessionid'] = sessionid
            return self.emit( msg )
        elif isinstance( msg, str ):
            return self.emit( { 'message':msg, 'sessionid':sessionid } )

    def start():
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

        # DEBUG: REMOVE ME
        # print "emitting: %s" % repr( ev )

        # connection event is special. adds to list
        if ev['eventid'] == 'KIPP0001':
            sessionid = ev['sessionno']
            self.sessions[sessionid] = \
                self.createSession(
                    ev['src_ip'], ev['src_port'], ev['dst_ip'], ev['dst_port'] )
            return

        # extract session id from the twisted log prefix
        if 'system' in ev:
            match = self.re_sessionlog.match(ev['system'])
            if not match:
                return
            sessionid = int(match.groups()[0])
        elif 'sessionid' in ev:
            sessionid = ev['sessionid']

        if sessionid not in self.sessions.keys():
            return

        if 'eventid' in ev:
            if ev['eventid'] in self.events:
                self.events[ev['eventid']]( self.sessions[sessionid], ev )
                return

        print "error, can't dblog %s" % repr(ev)

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

    # args has: logfile
    def handleTTYLogOpened(self, session, args):
        self.ttylogs[session] = args['logfile']

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
