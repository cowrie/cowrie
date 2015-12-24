# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *
from cowrie.core import utils

commands = {}

class command_last(HoneyPotCommand):
    def call(self):
        fn = '%s/lastlog.txt' % self.protocol.cfg.get('honeypot', 'data_path')
        if not os.path.exists(fn):
            return
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
        data = utils.tail(file(fn), numlines)
        self.write(''.join(data)+'\n')
commands['/usr/bin/last'] = command_last

# vim: set sw=4 et:
