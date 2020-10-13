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

    unique_lines = set()

    def start(self):
        if self.input_data:
            lines = self.input_data.split(b'\n')
            if not lines[-1]:
                lines.pop()

            self.unique_lines = set(lines)
            for line in self.unique_lines:
                self.writeBytes(line + b'\n')

            self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.command.input',
                realm='uniq',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

        self.grep_input(line)

    def handle_CTRL_D(self):
        self.exit()

    def grep_input(self, line):
        if line not in self.unique_lines:
            self.writeBytes(line.encode() + b'\n')
            self.unique_lines.add(line)


commands['/usr/bin/uniq'] = command_uniq
commands['uniq'] = command_uniq
