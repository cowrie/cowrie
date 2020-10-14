# Copyright (c) 2020 Peter Sufliarsky <sufliarskyp@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import absolute_import, division

import re

from cowrie.shell.command import HoneyPotCommand


commands = {}


class command_chmod(HoneyPotCommand):

    def call(self):
        # at least 2 arguments are expected
        if len(self.args) == 0:
            self.write('chmod: missing operand\n')
            self.write('Try \'chmod --help\' for more information.\n')
            return
        elif len(self.args) == 1:
            self.write('chmod: missing operand after ‘{}’\n'.format(self.args[0]))
            self.write('Try \'chmod --help\' for more information.\n')
            return

        # extract mode, options and files from the command arguments
        mode = None
        options = []
        files = []

        for arg in self.args:
            if re.match('-[cfvR]+', arg) or arg.startswith('--'):
                options.append(arg)
            elif mode is None:
                mode = arg
            else:
                files.append(arg)

        # mode has to match this regex
        mode_regex = '^[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=]?[0-7]{1,4}$'
        if not re.match(mode_regex, mode):
            # invalid mode was specified
            self.write('chmod: invalid mode: ‘{}’\n'.format(mode))
            self.write('Try \'chmod --help\' for more information.\n')
            return

        # go through the list of files and check whether they exist
        for file in files:
            if file != '*':
                path = self.fs.resolve_path(file, self.protocol.cwd)
                if not self.fs.exists(path):
                    self.write('chmod: cannot access \'{}\': No such file or directory\n'.format(file))


commands['/bin/chmod'] = command_chmod
commands['chmod'] = command_chmod
