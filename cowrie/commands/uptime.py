# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import division, absolute_import

import time

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core import utils

commands = {}


class command_uptime(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        self.write('%s  up %s,  1 user,  load average: 0.00, 0.00, 0.00\n' % \
            (time.strftime('%H:%M:%S'), utils.uptime(self.protocol.uptime())))

commands['/usr/bin/uptime'] = command_uptime

