# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import re
import random
import hashlib
import socket
import getopt

from twisted.internet import reactor

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_ping(HoneyPotCommand):

    def valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except:
            return False

    def start(self):
        self.host = None
        self.max = 0
        self.running = False

        try:
            optlist, args = getopt.getopt(self.args, "c:")
        except getopt.GetoptError as err:
            self.writeln('ping: %s' % err )
            self.exit()
            return

        for opt in optlist:
            if opt[0] == '-c':
                try:
                    self.max = int(opt[1])
                except:
                    self.max = 0
                if self.max <= 0:
                    self.writeln('ping: bad number of packets to transmit.')
                    self.exit()
                    return

        self.host = args[0].strip()

        if not self.host:
            for l in (
                    'Usage: ping [-LRUbdfnqrvVaA] [-c count] [-i interval] [-w deadline]',
                    '            [-p pattern] [-s packetsize] [-t ttl] [-I interface or address]',
                    '            [-M mtu discovery hint] [-S sndbuf]',
                    '            [ -T timestamp option ] [ -Q tos ] [hop1 ...] destination',
                    ):
                self.writeln(l)
            self.exit()
            return

        if re.match('^[0-9.]+$', self.host):
            if self.valid_ip(self.host):
                self.ip = self.host
            else:
                self.writeln('ping: unknown host %s' % self.host)
                self.exit()
        else:
            s = hashlib.md5(self.host).hexdigest()
            self.ip = '.'.join([str(int(x, 16)) for x in
                (s[0:2], s[2:4], s[4:6], s[6:8])])

        self.running = True
        self.writeln('PING %s (%s) 56(84) bytes of data.' % \
            (self.host, self.ip))
        self.scheduled = reactor.callLater(0.2, self.showreply)
        self.count = 0

    def showreply(self):
        ms = 40 + random.random() * 10
        self.writeln(
            '64 bytes from %s (%s): icmp_seq=%d ttl=50 time=%.1f ms' % \
            (self.host, self.ip, self.count + 1, ms))
        self.count += 1
        if self.count == self.max:
            self.running = False
            self.writeln('')
            self.printstatistics()
            self.exit()
        else:
            self.scheduled = reactor.callLater(1, self.showreply)

    def printstatistics(self):
        self.writeln('--- %s ping statistics ---' % self.host)
        self.writeln('%d packets transmitted, %d received, 0%% packet loss, time 907ms' % \
            (self.count, self.count))
        self.writeln('rtt min/avg/max/mdev = 48.264/50.352/52.441/2.100 ms')

    def handle_CTRL_C(self):
        if self.running == False:
            return HoneyPotCommand.handle_CTRL_C(self)
        else:
            self.writeln('^C')
            self.scheduled.cancel()
            self.printstatistics()
            self.exit()

commands['/bin/ping'] = command_ping
