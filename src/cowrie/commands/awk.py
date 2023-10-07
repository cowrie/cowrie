# Copyright (c) 2010 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information
# Contributor: Fosocles

"""
awk command

limited implementation that only supports `print` command.
"""

from __future__ import annotations

import getopt
import re
from re import Match

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}


class Command_awk(HoneyPotCommand):
    """
    awk command
    """

    # code is an array of dictionaries contain the regexes to match and the code to execute
    code: list[dict[str, str]]

    def start(self) -> None:
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

        for o, _a in optlist:
            if o in "--help":
                self.help()
                self.exit()
                return
            elif o in "--version":
                self.version()
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
                    self.errorWrite(f"awk: {arg}: Is a directory\n")
                    continue

                try:
                    contents = self.fs.file_contents(pname)
                    if contents:
                        self.output(contents)
                    else:
                        raise FileNotFound
                except FileNotFound:
                    self.errorWrite(f"awk: {arg}: No such file or directory\n")

        else:
            self.output(self.input_data)
        self.exit()

    def awk_parser(self, program: str) -> list[dict[str, str]]:
        """
        search for awk execution patterns, either direct {} code or only executed for a certain regex
        { }
        /regex/ { }
        """
        code = []
        re1 = r"\s*(\/(?P<pattern>\S+)\/\s+)?\{\s*(?P<code>[^\}]+)\}\s*"
        matches = re.findall(re1, program)
        for m in matches:
            code.append({"regex": m[1], "code": m[2]})
        return code

    def awk_print(self, words: str) -> None:
        """
        This is the awk `print` command that operates on a single line only
        """
        self.write(words)
        self.write("\n")

    def output(self, inb: bytes | None) -> None:
        """
        This is the awk output.
        """
        if inb:
            inp = inb.decode("utf-8")
        else:
            return

        inputlines = inp.split("\n")
        if inputlines[-1] == "":
            inputlines.pop()

        def repl(m: Match) -> str:
            try:
                return words[int(m.group(1))]
            except IndexError:
                return ""

        for inputline in inputlines:
            # split by whitespace and add full line in $0 as awk does.
            # TODO: change here to use custom field separator
            words = inputline.split()
            words.insert(0, inputline)

            for c in self.code:
                if re.match(c["regex"], inputline):
                    line = c["code"]
                    line = re.sub(r"\$(\d+)", repl, line)
                    # print("LINE1: {}".format(line))
                    if re.match(r"^print\s*", line):
                        # remove `print` at the start
                        line = re.sub(r"^\s*print\s+", "", line)
                        # remove whitespace at the end
                        line = re.sub(r"[;\s]*$", "", line)
                        # replace whitespace and comma by single space
                        line = re.sub(r"(,|\s+)", " ", line)
                        # print("LINE2: {}".format(line))
                        self.awk_print(line)

    def lineReceived(self, line: str) -> None:
        """
        This function logs standard input from the user send to awk
        """
        log.msg(
            eventid="cowrie.session.input",
            realm="awk",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

        self.output(line.encode())

    def handle_CTRL_D(self) -> None:
        """
        ctrl-d is end-of-file, time to terminate
        """
        self.exit()

    def help(self) -> None:
        self.write(
            """Usage: awk [POSIX or GNU style options] -f progfile [--] file ...
Usage: awk [POSIX or GNU style options] [--] 'program' file ...
POSIX options:          GNU long options: (standard)
        -f progfile             --file=progfile
        -F fs                   --field-separator=fs
        -v var=val              --assign=var=val
Short options:          GNU long options: (extensions)
        -b                      --characters-as-bytes
        -c                      --traditional
        -C                      --copyright
        -d[file]                --dump-variables[=file]
        -D[file]                --debug[=file]
        -e 'program-text'       --source='program-text'
        -E file                 --exec=file
        -g                      --gen-pot
        -h                      --help
        -i includefile          --include=includefile
        -l library              --load=library
        -L[fatal|invalid]       --lint[=fatal|invalid]
        -M                      --bignum
        -N                      --use-lc-numeric
        -n                      --non-decimal-data
        -o[file]                --pretty-print[=file]
        -O                      --optimize
        -p[file]                --profile[=file]
        -P                      --posix
        -r                      --re-interval
        -S                      --sandbox
        -t                      --lint-old
        -V                      --version

To report bugs, see node `Bugs' in `gawk.info', which is
section `Reporting Problems and Bugs' in the printed version.

gawk is a pattern scanning and processing language.
By default it reads standard input and writes standard output.

Examples:
        gawk '{ sum += $1 }; END { print sum }' file
        gawk -F: '{ print $1 }' /etc/passwd
"""
        )

    def version(self) -> None:
        self.write(
            """GNU Awk 4.1.4, API: 1.1 (GNU MPFR 4.0.1, GNU MP 6.1.2)
Copyright (C) 1989, 1991-2016 Free Software Foundation.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see http://www.gnu.org/licenses/.
"""
        )


commands["/bin/awk"] = Command_awk
commands["awk"] = Command_awk
