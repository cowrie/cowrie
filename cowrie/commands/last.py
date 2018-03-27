# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import division, absolute_import

from cowrie.shell.honeypot import HoneyPotCommand
from cowrie.shell.fs import *
from cowrie.core import utils

from cowrie.core.config import CONFIG

commands = {}


class command_last(HoneyPotCommand):

    def call(self):
        l = list(self.args)
        numlines = 25
        while len(l):
            arg = l.pop(0)
            if not arg.startswith('-'):
                continue
            elif arg[1:].isdigit():
                numlines = int(arg[1:])
            elif arg == '-n' and len(l) and l[0].isdigit():
                numlines = int(l.pop(0))

        self.write('%-8s %-12s %-16s %s   still logged in\n' % \
            (self.protocol.user.username, "pts/0", self.protocol.clientIP,
             time.strftime('%a %b %d %H:%M', time.localtime(self.protocol.logintime)) ))

        self.write("\n")
        self.write("wtmp begins %s\n" % \
             time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(self.protocol.logintime // (3600*24) * (3600*24) + 63 )) )


commands['/usr/bin/last'] = command_last

# vim: set sw=4 et:
