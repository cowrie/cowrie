# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
"""

import time
import re
import hashlib
import getopt
import socket

from twisted.python import log
from twisted.internet import reactor

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_ssh(HoneyPotCommand):
    """
    """

    def valid_ip(self, address):
        """
        """
        try:
            socket.inet_aton(address)
            return True
        except:
            return False


    def start(self):
        """
        """
        try:
            optlist, args = getopt.getopt(self.args,
                '-1246AaCfgKkMNnqsTtVvXxYb:c:D:e:F:i:L:l:m:O:o:p:R:S:w:')
        except getopt.GetoptError as err:
            self.write('Unrecognized option\n')
            self.exit()
        for opt in optlist:
            if opt[0] == '-V':
                self.write('OpenSSH_6.7p1 Debian-5, OpenSSL 1.0.1k 8 Jan 2015\n')
                self.exit()
                return
        if not len(args):
            for l in (
                    'usage: ssh [-1246AaCfgKkMNnqsTtVvXxY] [-b bind_address] [-c cipher_spec]',
                    '           [-D [bind_address:]port] [-e escape_char] [-F configfile]',
                    '           [-i identity_file] [-L [bind_address:]port:host:hostport]',
                    '           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]',
                    '           [-R [bind_address:]port:host:hostport] [-S ctl_path]',
                    '           [-w local_tun[:remote_tun]] [user@]hostname [command]',
                    ):
                self.write(l+'\n')
            self.exit()
            return
        user, host = 'root', args[0]
        for opt in optlist:
            if opt[0] == '-l':
                user = opt[1]
        if args[0].count('@'):
            user, host = args[0].split('@', 1)

        if re.match('^[0-9.]+$', host):
            if self.valid_ip(host):
                self.ip = host
            else:
                self.write('ssh: Could not resolve hostname %s: Name or service not known\n' % (host,))
                self.exit()
        else:
            s = hashlib.md5(host).hexdigest()
            self.ip = '.'.join([str(int(x, 16)) for x in
                (s[0:2], s[2:4], s[4:6], s[6:8])])

        self.host = host
        self.user = user

        self.write('The authenticity of host \'%s (%s)\' can\'t be established.\n' % \
            (self.host, self.ip))
        self.write('RSA key fingerprint is 9d:30:97:8a:9e:48:0d:de:04:8d:76:3a:7b:4b:30:f8.\n')
        self.write('Are you sure you want to continue connecting (yes/no)? ')
        self.callbacks = [self.yesno, self.wait]


    def yesno(self, line):
        """
        """
        self.write(
            'Warning: Permanently added \'%s\' (RSA) to the list of known hosts.\n' % \
            self.host)
        self.write('%s@%s\'s password: ' % (self.user, self.host))
        self.protocol.password_input = True


    def wait(self, line):
        """
        """
        reactor.callLater(2, self.finish, line)


    def finish(self, line):
        """
        """
        self.pause = False
        rest, host = self.host, 'localhost'
        rest = self.host.strip().split('.')
        if len(rest) and rest[0].isalpha():
            host = rest[0]
        self.protocol.hostname = host
        self.protocol.cwd = '/root'
        if not self.fs.exists(self.protocol.cwd):
            self.protocol.cwd = '/'
        self.protocol.password_input = False
        self.write(
            'Linux %s 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:37 UTC 2009 i686\n' % \
            (self.protocol.hostname,))
        self.write('Last login: %s from 192.168.9.4\n' % \
            (time.ctime(time.time() - 123123),))
        self.exit()


    def lineReceived(self, line):
        """
        """
        log.msg( 'INPUT (ssh):', line )
        if len(self.callbacks):
            self.callbacks.pop(0)(line)
commands['/usr/bin/ssh'] = command_ssh

# vim: set sw=4 et:
