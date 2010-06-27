# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from kippo.core.honeypot import HoneyPotCommand
from kippo.core.fs import *
from kippo.core.config import config
from kippo.core import utils
import stat, time, anydbm

commands = {}

class command_last(HoneyPotCommand):
    def call(self):
        db = anydbm.open('%s/lastlog.db' % \
            config().get('honeypot', 'data_path'), 'c')
        count = 0
        for k in sorted(db.keys(), reverse=True):
            self.writeln(db[k])
            count += 1
            if count >= 25:
                break
commands['/usr/bin/last'] = command_last

# vim: set sw=4 et:
