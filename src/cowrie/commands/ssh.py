# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import absolute_import, division

import getopt
import hashlib
import re
import socket
import time

from twisted.internet import reactor
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand

commands = {}


OUTPUT = [
    'usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]',
    '           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]',
    '           [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11]',
    '           [-i identity_file] [-J [user@]host[:port]] [-L address]',
    '           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]',  # noqa
    '           [-Q query_option] [-R address] [-S ctl_path] [-W host:port]',
    '           [-w local_tun[:remote_tun]] destination [command]'
]


class command_ssh(HoneyPotCommand):

    def valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except Exception:
            return False

    def start(self):
        try:
            options = '-1246AaCfgKkMNnqsTtVvXxYb:c:D:e:F:i:L:l:m:O:o:p:R:S:w:'
            optlist, args = getopt.getopt(self.args, options)
        except getopt.GetoptError:
            self.write('Unrecognized option\n')
            self.exit()
        for opt in optlist:
            if opt[0] == '-V':
                self.write(CowrieConfig().get('shell', 'ssh_version',
                           fallback="OpenSSH_7.9p1, OpenSSL 1.1.1a  20 Nov 2018")+"\n")
                self.exit()
                return
        if not len(args):
            for l in OUTPUT:
                self.write('{0}\n'.format(l))
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
                self.write('ssh: Could not resolve hostname %s: \
                    Name or service not known\n' % (host,))
                self.exit()
        else:
            s = hashlib.md5(host).hexdigest()
            self.ip = '.'.join([str(int(x, 16)) for x in
                                (s[0:2], s[2:4], s[4:6], s[6:8])])

        self.host = host
        self.user = user

        self.write('The authenticity of host \'%s (%s)\' \
            can\'t be established.\n' % (self.host, self.ip))
        self.write('RSA key fingerprint is \
            9d:30:97:8a:9e:48:0d:de:04:8d:76:3a:7b:4b:30:f8.\n')
        self.write('Are you sure you want to continue connecting (yes/no)? ')
        self.callbacks = [self.yesno, self.wait]

    def yesno(self, line):
        self.write('Warning: Permanently added \'{}\' (RSA) to the \
            list of known hosts.\n'.format(self.host))
        self.write('%s@%s\'s password: ' % (self.user, self.host))
        self.protocol.password_input = True

    def wait(self, line):
        reactor.callLater(2, self.finish, line)

    def finish(self, line):
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
        self.write('Linux {} 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:37 \
            UTC 2009 i686\n'.format(self.protocol.hostname))
        self.write('Last login: %s from 192.168.9.4\n'
                   % (time.ctime(time.time() - 123123),))
        self.exit()

    def lineReceived(self, line):
        log.msg('INPUT (ssh):', line)
        if len(self.callbacks):
            self.callbacks.pop(0)(line)


commands['/usr/bin/ssh'] = command_ssh
commands['ssh'] = command_ssh
