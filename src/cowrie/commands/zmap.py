# Copyright (c) 2020 Peter Sufliarsky <sufliarskyp@gmail.com>

from __future__ import absolute_import, division

import time

from cowrie.shell.command import HoneyPotCommand

commands = {}


class command_zmap(HoneyPotCommand):

    def call(self):
        self.write('%s.883 [FATAL] zmap: target port (-p) is required for this type of probe\n' %
                   (time.strftime('%b %d %H:%M:%S')))


commands['/usr/bin/zmap'] = command_zmap
commands['zmap'] = command_zmap
