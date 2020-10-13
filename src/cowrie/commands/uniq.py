# Copyright (c) 2020 Peter Sufliarsky <sufliarskyp@gmail.com>
# See the COPYRIGHT file for more information


"""
uniq command
"""

from __future__ import absolute_import, division

from twisted.python import log
from cowrie.shell.command import HoneyPotCommand

commands = {}


class command_uniq(HoneyPotCommand):

    def start(self):
        lines = self.input_data.split(b'\n')
        unique_lines = set(lines)
        for line in unique_lines:
            if line:
                self.writeBytes(line + b'\n')

        self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.command.input',
                realm='uniq',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

    def handle_CTRL_D(self):
        self.exit()


commands['/usr/bin/uniq'] = command_uniq
commands['uniq'] = command_uniq