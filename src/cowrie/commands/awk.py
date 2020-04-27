# Copyright (c) 2010 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
awk command

limited implementation that only supports `print` command.
"""

from __future__ import absolute_import, division

import getopt
import re

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}


class command_awk(HoneyPotCommand):
    """
    awk command
    """

    # code is an array of dictionaries contain the regexes to match and the code to execute
    code = []

    def start(self):
        try:
            optlist, args = getopt.gnu_getopt(self.args, "Fvf", ["version"])
        except getopt.GetoptError as err:
            self.errorWrite(
                "awk: invalid option -- '{}'\nTry 'awk --help' for more information.\n".format(
                    err.opt
                )
            )
            self.exit()
            return

        for o, a in optlist:
            if o in "--help":
                self.help()
                self.exit()
                return
            elif o in "--version":
                self.help()
                self.exit()
                return
            elif o in ("-n", "--number"):
                pass

        # first argument is program (generally between quotes if contains spaces)
        # second and onward arguments are files to operate on

        if len(args) == 0:
            self.help()
            self.exit()
            return

        self.code = self.awk_parser(args.pop(0))

        if len(args) > 0:
            for arg in args:
                if arg == "-":
                    self.output(self.input_data)
                    continue

                pname = self.fs.resolve_path(arg, self.protocol.cwd)

                if self.fs.isdir(pname):
                    self.errorWrite("awk: {}: Is a directory\n".format(arg))
                    continue

                try:
                    contents = self.fs.file_contents(pname)
                    if contents:
                        self.output(contents)
                    else:
                        raise FileNotFound
                except FileNotFound:
                    self.errorWrite("awk: {}: No such file or directory\n".format(arg))

        else:
            self.output(self.input_data)
        self.exit()

    def awk_parser(self, program):
        """
        search for awk execution patterns, either direct {} code or only executed for a certain regex
        { }
        /regex/ { }
        """
        code = []
        # print("awk_parser program: {}".format(program))
        re1 = r'\s*(\/(?P<pattern>\S+)\/\s+)?\{\s*(?P<code>[^\}]+)\}\s*'
        matches = re.findall(re1, program)
        for m in matches:
            code.append({'regex': m[1], 'code': m[2]})
        return code

    def awk_print(self, words):
        """
        This is the awk `print` command that operates on a single line only
        """
        self.write(words)
        self.write('\n')

    def output(self, input):
        """
        This is the awk output.
        """
        if "decode" in dir(input):
            input = input.decode('utf-8')
        if not isinstance(input, str):
            pass

        inputlines = input.split('\n')
        if inputlines[-1] == "":
            inputlines.pop()
        for inputline in inputlines:

            # split by whitespace and add full line in $0 as awk does.
            # TODO: change here to use custom field separator
            words = inputline.split()
            words.insert(0, inputline)

            def repl(m):
                try:
                    return words[int(m.group(1))]
                except IndexError:
                    return ""

            for c in self.code:
                if re.match(c['regex'], inputline):
                    line = c['code']
                    line = re.sub(r'\$(\d+)', repl, line)
                    # print("LINE1: {}".format(line))
                    if re.match(r'^print\s*', line):
                        # remove `print` at the start
                        line = re.sub(r'^\s*print\s+', '', line)
                        # replace whitespace and comma by single space
                        line = re.sub(r'(,|\s+)', ' ', line)
                        # print("LINE2: {}".format(line))
                        self.awk_print(line)

    def lineReceived(self, line):
        """
        This function logs standard input from the user send to awk
        """
        log.msg(
            eventid="cowrie.session.input",
            realm="awk",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

        self.output(line)

    def handle_CTRL_D(self):
        """
        ctrl-d is end-of-file, time to terminate
        """
        self.exit()

    def help(self):
        self.write(
            """TODO: awk help message
"""
        )


commands["/bin/awk"] = command_awk
commands["awk"] = command_awk
