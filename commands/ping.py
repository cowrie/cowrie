from core.honeypot import HoneyPotCommand
from twisted.internet import reactor
import time, re, random, md5

commands = {}

class command_ping(HoneyPotCommand):
    def start(self):
        if not len(self.args.strip()):
            for l in (
                    'Usage: ping [-LRUbdfnqrvVaA] [-c count] [-i interval] [-w deadline]',
                    '            [-p pattern] [-s packetsize] [-t ttl] [-I interface or address]',
                    '            [-M mtu discovery hint] [-S sndbuf]',
                    '            [ -T timestamp option ] [ -Q tos ] [hop1 ...] destination',
                    ):
                self.writeln(l)
            self.exit()
            return

        self.host = self.args.strip()
        if re.match('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$',
                self.host):
            self.ip = self.host
        else:
            s = md5.md5(self.host).hexdigest()
            self.ip = '.'.join([str(int(x, 16)) for x in
                (s[0:2], s[2:4], s[4:6], s[6:8])])

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
        self.scheduled = reactor.callLater(1, self.showreply)

    def ctrl_c(self):
        self.scheduled.cancel()
        self.writeln('--- %s ping statistics ---' % self.host)
        self.writeln('%d packets transmitted, %d received, 0%% packet loss, time 907ms' % \
            (self.count, self.count))
        self.writeln('rtt min/avg/max/mdev = 48.264/50.352/52.441/2.100 ms')
        self.exit()
commands['/bin/ping'] = command_ping
