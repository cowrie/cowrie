# -*- coding: utf-8 -*-                                                                                             
# Copyright (c) 2014 Peter Reuterås <peter@reuteras.com>
# See the COPYRIGHT file for more information

import os
import getopt

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *

commands = {}

class command_nohup(HoneyPotCommand):
    def call(self):
        if not len(self.args):
            self.writeln('nohup: missing operand')
            self.writeln('Try `nohup --help\' for more information.')
            return
        path = self.fs.resolve_path("nohup.out", self.honeypot.cwd)
        if self.fs.exists(path):
            return
        self.fs.mkfile(path, 0, 0, 0, 33188)
        self.writeln("nohup: ignoring input and appending output to 'nohup.out'")

commands['/usr/bin/nohup'] = command_nohup

# vim: set sw=4 et:
