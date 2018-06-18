# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
cat command

TODO: support for '-' (stdin marked as '-')
"""

from __future__ import division, absolute_import

import getopt
import copy
from os import path

from cowrie.shell.honeypot import HoneyPotCommand
from cowrie.shell.fs import *

commands = {}

class command_cat(HoneyPotCommand):
    """
    cat command
    """

    number = False
    linenumber = 1

    def start(self):
        """
        """
        try:
            optlist, args = getopt.gnu_getopt(self.args, 'AbeEnstTuv', ['help', 'number', 'version'])
        except getopt.GetoptError as err:
            self.errorWrite("cat: invalid option -- '{}'\nTry 'cat --help' for more information.\n".format(err.opt))
            self.exit()
            return

        for o, a in optlist:
            if o in ('--help'):
                self.help()
                self.exit()
                return
            elif o in ('-n', '--number'):
                self.number = True

        if self.input_data:
            self.output(self.input_data)
        else:
            for arg in args:
                pname = self.fs.resolve_path(arg, self.protocol.cwd)

                if self.fs.isdir(pname):
                    self.errorWrite('cat: {}: Is a directory\n'.format(arg))
                    continue

                try:
                    contents = self.fs.file_contents(pname)
                    if contents:
                        self.output(contents)
                    else:
                        raise FileNotFound
                except FileNotFound:
                    self.errorWrite('cat: {}: No such file or directory\n'.format(arg))
        self.exit()


    def output(self, input):
        """
        This is the cat output, with optional line numbering
        """
        lines = input.split('\n')
        if lines[-1] == "":
            lines.pop()
        for line in lines:
            if self.number:
                self.write("{:>6}  ".format(self.linenumber))
                self.linenumber = self.linenumber + 1
            self.write(line+"\n")


    def lineReceived(self, line):
        """
        This function logs standard input from the user send to cat
        """
        log.msg(eventid='cowrie.session.input',
                realm='cat',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

        self.output(line)


    def handle_CTRL_D(self):
        """
        ctrl-d is end-of-file, time to terminate
        """
        self.exit()


    def help(self):
        """
        """
        self.write(
"""Usage: cat [OPTION]... [FILE]...
Concatenate FILE(s) to standard output.

With no FILE, or when FILE is -, read standard input.

  -A, --show-all           equivalent to -vET
  -b, --number-nonblank    number nonempty output lines, overrides -n
  -e                       equivalent to -vE
  -E, --show-ends          display $ at end of each line
  -n, --number             number all output lines
  -s, --squeeze-blank      suppress repeated empty output lines
  -t                       equivalent to -vT
  -T, --show-tabs          display TAB characters as ^I
  -u                       (ignored)
  -v, --show-nonprinting   use ^ and M- notation, except for LFD and TAB
      --help     display this help and exit
      --version  output version information and exit

Examples:
  cat f - g  Output f's contents, then standard input, then g's contents.
  cat        Copy standard input to standard output.

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/cat>
or available locally via: info '(coreutils) cat invocation'
""")

commands['/bin/cat'] = command_cat
