# Copyright (c) 2020 Matej Dujava <mdujava@kocurkovo.cz>
# See the COPYRIGHT file for more information
"""
tee command

"""

from __future__ import absolute_import, division

import getopt
import os

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}


class command_tee(HoneyPotCommand):
    """
    tee command
    """

    append = False
    teeFiles = []
    writtenBytes = 0
    ignoreInterupts = False

    def start(self):
        try:
            optlist, args = getopt.gnu_getopt(self.args, 'aip', ['help', 'append', 'version'])
        except getopt.GetoptError as err:
            self.errorWrite("tee: invalid option -- '{}'\nTry 'tee --help' for more information.\n".format(err.opt))
            self.exit()
            return

        for o, a in optlist:
            if o in ('--help'):
                self.help()
                self.exit()
                return
            elif o in ('-a', '--append'):
                self.append = True
            elif o in ('-a', '--ignore-interrupts'):
                self.ignoreInterupts = True

        for arg in args:
            pname = self.fs.resolve_path(arg, self.protocol.cwd)

            if self.fs.isdir(pname):
                self.errorWrite('tee: {}: Is a directory\n'.format(arg))
                continue

            try:
                pname = self.fs.resolve_path(arg, self.protocol.cwd)

                folder_path = os.path.dirname(pname)

                if not self.fs.exists(folder_path) or not self.fs.isdir(folder_path):
                    raise FileNotFound

                self.teeFiles.append(pname)
                self.fs.mkfile(pname, 0, 0, 0, 0o644)

            except FileNotFound:
                self.errorWrite('tee: {}: No such file or directory\n'.format(arg))

        if self.input_data:
            self.output(self.input_data)
            self.exit()

    def write_to_file(self, data):
        self.writtenBytes += len(data)
        for outf in self.teeFiles:
            self.fs.update_size(outf, self.writtenBytes)

    def output(self, input):
        """
        This is the tee output, if no file supplied
        """
        if 'decode' in dir(input):
            input = input.decode('UTF-8')
        if not isinstance(input, str):
            pass

        lines = input.split('\n')
        if lines[-1] == "":
            lines.pop()
        for line in lines:
            self.write(line + '\n')
            self.write_to_file(line + '\n')

    def lineReceived(self, line):
        """
        This function logs standard input from the user send to tee
        """
        log.msg(eventid='cowrie.session.input',
                realm='tee',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

        self.output(line)

    def handle_CTRL_C(self):
        if not self.ignoreInterupts:
            log.msg('Received CTRL-C, exiting..')
            self.write('^C\n')
            self.exit()

    def handle_CTRL_D(self):
        """
        ctrl-d is end-of-file, time to terminate
        """
        self.exit()

    def help(self):
        self.write(
            """Usage: tee [OPTION]... [FILE]...
Copy standard input to each FILE, and also to standard output.

  -a, --append              append to the given FILEs, do not overwrite
  -i, --ignore-interrupts   ignore interrupt signals
  -p                        diagnose errors writing to non pipes
      --output-error[=MODE]   set behavior on write error.  See MODE below
      --help     display this help and exit
      --version  output version information and exit

MODE determines behavior with write errors on the outputs:
  'warn'         diagnose errors writing to any output
  'warn-nopipe'  diagnose errors writing to any output not a pipe
  'exit'         exit on error writing to any output
  'exit-nopipe'  exit on error writing to any output not a pipe
The default MODE for the -p option is 'warn-nopipe'.
The default operation when --output-error is not specified, is to
exit immediately on error writing to a pipe, and diagnose errors
writing to non pipe outputs.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation <https://www.gnu.org/software/coreutils/tee>
or available locally via: info '(coreutils) tee invocation'
"""
        )


commands['/bin/tee'] = command_tee
commands['tee'] = command_tee
