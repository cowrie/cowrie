# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import re, time, datetime, socket

class DBLogger(object):
    def __init__(self, cfg):
        self.sessions = {}
        self.ttylogs = {}
        self.re_unique = re.compile('.*(SSHServerTransport,[0-9]+,[0-9.]+)$')
        self.re_map = [(re.compile(x[0]), x[1]) for x in (
            ('^connection lost$',
                self._connectionLost),
            ('^login attempt \[(?P<username>.*)/(?P<password>.*)\] failed',
                self.handleLoginFailed),
            ('^login attempt \[(?P<username>.*)/(?P<password>.*)\] succeeded',
                self.handleLoginSucceeded),
            ('^Opening TTY log: (?P<logfile>.*)$',
                self.handleTTYLogOpened),
            ('^Command found: (?P<input>.*)$',
                self.handleCommand),
            ('^Command not found: (?P<input>.*)$',
                self.handleUnknownCommand),
            ('^INPUT \((?P<realm>[a-zA-Z0-9]+)\): (?P<input>.*)$',
                self.handleInput),
            )]
        self.start(cfg)

        if cfg.has_option('honeypot', 'sensor_name'):
            self.sensor = cfg.get('honeypot', 'sensor_name')
        else:
            self.sensor = socket.gethostbyaddr(socket.gethostname())[2][0]

    def start():
        pass

    def nowUnix(self):
        """return the current UTC time as an UNIX timestamp"""
        return int(time.mktime(datetime.datetime.utcnow().utctimetuple()))

    def uniqstr(self, system):
        matches = self.re_unique.match(system)
        return matches.groups()[0]

    def emit(self, ev):
        if ev['system'] == '-':
            return
        match = self.re_unique.match(ev['system'])
        if not match:
            return
        uniqstr = match.groups()[0]
        if uniqstr not in self.sessions.keys():
            ip = uniqstr.split(',')[2]
            session = self.createSession(ip)
            self.sessions[uniqstr] = session
        else:
            session = self.sessions[uniqstr]
        message = ev['message'][0]
        for regex, func in self.re_map:
            match = regex.match(message)
            if match:
                func(session, match.groupdict())
                break

    def _connectionLost(self, session, args):
        self.handleConnectionLost(session, args)
        if session in self.ttylogs:
            del self.ttylogs[session]
        for i in [x for x in self.sessions if self.sessions[x] == session]:
            del self.sessions[i]

    # We have to return an unique ID
    def createSession(self, ip):
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

# vim: set sw=4 et:
