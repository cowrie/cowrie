# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import re, time, socket

class DBLogger(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions = {}
        self.ttylogs = {}
        self.re_connected = re.compile(
            '^New connection: ([0-9.]+):([0-9]+) \(([0-9.]+):([0-9]+)\) ' + \
            '\[session: ([0-9]+)\]$')
        self.re_sessionlog = re.compile(
            '.*HoneyPotTransport,([0-9]+),[0-9.]+$')

        # :dispatch: means the message has been delivered directly via
        # logDispatch, instead of relying on the twisted logging, which breaks
        # on scope changes.
        self.re_map = [(re.compile(x[0]), x[1]) for x in (
            ('^connection lost$',
                self._connectionLost),
            ('^login attempt \[(?P<username>.*)/(?P<password>.*)\] failed',
                self.handleLoginFailed),
            ('^login attempt \[(?P<username>.*)/(?P<password>.*)\] succeeded',
                self.handleLoginSucceeded),
            ('^Opening TTY log: (?P<logfile>.*)$',
                self.handleTTYLogOpened),
            ('^:dispatch: Command found: (?P<input>.*)$',
                self.handleCommand),
            ('^:dispatch: Command not found: (?P<input>.*)$',
                self.handleUnknownCommand),
            ('^:dispatch: Saving URL \((?P<url>.*)\) to (?P<outfile>.*)$',
                self.handleFileDownload),
            ('^INPUT \((?P<realm>[a-zA-Z0-9]+)\): (?P<input>.*)$',
                self.handleInput),
            ('^Terminal size: (?P<height>[0-9]+) (?P<width>[0-9]+)$',
                self.handleTerminalSize),
            ('^Remote SSH version: (?P<version>.*)$',
                self.handleClientVersion),
            )]
        self.start(cfg)

    def logDispatch(self, sessionid, msg):
        if sessionid not in self.sessions.keys():
            return
        for regex, func in self.re_map:
            match = regex.match(msg)
            if match:
                func(self.sessions[sessionid], match.groupdict())
                break

    def start():
        pass

    def getSensor(self):
        if self.cfg.has_option('honeypot', 'sensor_name'):
            return self.cfg.get('honeypot', 'sensor_name')
        return None

    def nowUnix(self):
        """return the current UTC time as an UNIX timestamp"""
        return int(time.mktime(time.gmtime()[:-1] + (-1,)))

    def emit(self, ev):
        if not len(ev['message']):
            return
        match = self.re_connected.match(ev['message'][0])
        if match:
            sessionid = int(match.groups()[4])
            self.sessions[sessionid] = \
                self.createSession(
                    match.groups()[0], int(match.groups()[1]),
                    match.groups()[2], int(match.groups()[3]))
            return
        match = self.re_sessionlog.match(ev['system'])
        if not match:
            return
        sessionid = int(match.groups()[0])
        if sessionid not in self.sessions.keys():
            return
        message = ev['message'][0]
        for regex, func in self.re_map:
            match = regex.match(message)
            if match:
                func(self.sessions[sessionid], match.groupdict())
                break

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

    # We have to return an unique ID
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
