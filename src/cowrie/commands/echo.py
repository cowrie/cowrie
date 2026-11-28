# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import codecs
import getopt
import re
from typing import TYPE_CHECKING

from twisted.logger import Logger

from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_echo(HoneyPotCommand):
    _log = Logger()

    def call(self) -> None:
        newline = True
        escape_decode = False

        try:
            optlist, args = getopt.getopt(self.args, "eEn")
            for opt in optlist:
                if opt[0] == "-e":
                    escape_decode = True
                elif opt[0] == "-E":
                    escape_decode = False
                elif opt[0] == "-n":
                    newline = False
        except Exception:
            args = self.args

        try:
            # replace r'\\x' with r'\x'
            string = " ".join(args).replace(r"\\x", r"\x")

            # replace single character escape \x0 with \x00
            string = re.sub(
                r"(?<=\\)x([0-9a-fA-F])(?=\\|\"|\'|\s|$)", r"x0\g<1>", string
            )

            # if the string ends with \c escape, strip it and set newline flag to False
            if string.endswith("\\c"):
                string = string[:-2]
                newline = False

            if newline is True:
                string += "\n"

            if escape_decode:
                data: bytes = codecs.escape_decode(string)[0]
                self.writeBytes(data)
            else:
                self.write(string)

        except ValueError:
            self._log.info("echo command received Python incorrect hex escape")


commands["/bin/echo"] = Command_echo
commands["echo"] = Command_echo
