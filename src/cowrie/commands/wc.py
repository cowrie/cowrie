# Copyright (c) 2019 Nuno Novais <nuno@noais.me>
# All rights reserved.
# All rights given to Cowrie project

"""
This module contains the wc commnad
"""

from __future__ import absolute_import, division

import getopt
import re

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand

commands = {}


class command_wc(HoneyPotCommand):
    """
    wc command
    """

    def version(self):
        self.writeBytes(b'wc (GNU coreutils) 8.30\n')
        self.writeBytes(b'Copyright (C) 2018 Free Software Foundation, Inc.\n')
        self.writeBytes(b'License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n')
        self.writeBytes(b'This is free software: you are free to change and redistribute it.\n')
        self.writeBytes(b'There is NO WARRANTY, to the extent permitted by law.\n')
        self.writeBytes(b'\n')
        self.writeBytes(b'Written by Paul Rubin and David MacKenzie.\n')

    def help(self):
        self.writeBytes(b'Usage: wc [OPTION]... [FILE]...\n')
        self.writeBytes(b'Print newline, word, and byte counts for each FILE, and a total line if\n')
        self.writeBytes(b'more than one FILE is specified.  A word is a non-zero-length sequence of\n')
        self.writeBytes(b'characters delimited by white space.\n')
        self.writeBytes(b'\n')
        self.writeBytes(b'With no FILE, or when FILE is -, read standard input.\n')
        self.writeBytes(b'\n')
        self.writeBytes(b'The options below may be used to select which counts are printed, always in\n')
        self.writeBytes(b'the following order: newline, word, character, byte, maximum line length.\n')
        self.writeBytes(b'\t-c\tprint the byte counts\n')
        self.writeBytes(b'\t-m\tprint the character counts\n')
        self.writeBytes(b'\t-l\tprint the newline counts\n')
        self.writeBytes(b'\t-w\tprint the word counts\n')
        self.writeBytes(b'\t-h\tdisplay this help and exit\n')
        self.writeBytes(b'\t-v\toutput version information and exit\n')

    def wc_get_contents(self, filename, optlist):
        try:
            contents = self.fs.file_contents(filename)
            self.wc_application(contents, optlist)
        except Exception:
            self.errorWrite("wc: {}: No such file or directory\n".format(filename))

    def wc_application(self, contents, optlist):
        for opt, arg in optlist:
            if opt == "-l":
                contentsplit = contents.split(b'\n')
                self.write("{}\n".format(len(contentsplit) - 1))
            elif opt == "-w":
                contentsplit = re.sub(' +', ' ', contents.decode().strip('\n').strip()).split(' ')
                self.write("{}\n".format(len(contentsplit)))
            elif opt == "-m" or opt == "-c":
                self.write("{}\n".format(len(contents)))
            elif opt == '-v':
                self.version()
            else:
                self.help()

    def start(self):
        if not self.args:
            self.exit()
            return

        if self.args[0] == '>':
            pass
        else:
            try:
                optlist, args = getopt.getopt(self.args, 'cmlLwhv')
            except getopt.GetoptError as err:
                self.errorWrite("wc: invalid option -- {}\n".format(err.opt))
                self.help()
                self.exit()
                return
            for opt in optlist:
                if opt[0] == '-v':
                    self.version()
                    self.exit()
                    return
                if opt[0] == '-h':
                    self.help()
                    self.exit()
                    return

        if not self.input_data:
            files = self.check_arguments('wc', args[1:])
            for pname in files:
                self.wc_get_contents(pname, optlist)
        else:
            self.wc_application(self.input_data, optlist)

        self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.command.input',
                realm='wc',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

    def handle_CTRL_D(self):
        self.exit()


commands['/usr/bin/wc'] = command_wc
commands['/bin/wc'] = command_wc
commands['wc'] = command_wc
