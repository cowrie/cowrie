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
            self.write('nohup: missing operand\n')
            self.write('Try `nohup --help\' for more information.\n')
            return
        path = self.fs.resolve_path("nohup.out", self.protocol.cwd)
        if self.fs.exists(path):
            return
        self.fs.mkfile(path, 0, 0, 0, 33188)
        self.write("nohup: ignoring input and appending output to 'nohup.out'\n")

commands['/usr/bin/nohup'] = command_nohup

# vim: set sw=4 et:
