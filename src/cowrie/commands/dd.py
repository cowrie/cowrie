# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
dd commands
"""

from __future__ import annotations

import re

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}


class Command_dd(HoneyPotCommand):
    """
    dd command
    """

    ddargs: dict[str, str]

    def start(self) -> None:
        if not self.args or self.args[0] == ">":
            return

        self.ddargs = {}

        for arg in self.args:
            if arg.find("=") == -1:
                self.write(f"unknown operand: {arg}")
                HoneyPotCommand.exit(self)
            operand, value = arg.split("=")
            if operand not in ("if", "bs", "of", "count"):
                self.write(f"unknown operand: {operand}")
                self.exit(success=False)
            self.ddargs[operand] = value

        if self.input_data:
            self.writeBytes(self.input_data)
        else:
            bSuccess = True
            c = -1
            block = 512
            if "if" in self.ddargs:
                iname = self.ddargs["if"]
                pname = self.fs.resolve_path(iname, self.protocol.cwd)
                if self.fs.isdir(pname):
                    self.errorWrite(f"dd: {iname}: Is a directory\n")
                    bSuccess = False

                if bSuccess and "bs" in self.ddargs:
                    block = parse_size(self.ddargs["bs"])
                    if block <= 0:
                        self.errorWrite(f"dd: invalid number '{block}'\n")
                        bSuccess = False

                if bSuccess and "count" in self.ddargs:
                    c = int(self.ddargs["count"])
                    if c < 0:
                        self.errorWrite(f"dd: invalid number '{c}'\n")
                        bSuccess = False

                if bSuccess:
                    try:
                        contents = self.fs.file_contents(pname)
                        if c == -1:
                            self.writeBytes(contents)
                        else:
                            tsize = block * c
                            data = contents
                            if len(data) > tsize:
                                self.writeBytes(data[:tsize])
                            else:
                                self.writeBytes(data)
                    except FileNotFound:
                        self.errorWrite(f"dd: {iname}: No such file or directory\n")
                        bSuccess = False

                self.exit(success=bSuccess)

    def exit(self, success: bool = True) -> None:
        if success is True:
            self.write("0+0 records in\n")
            self.write("0+0 records out\n")
            self.write("0 bytes transferred in 0.695821 secs (0 bytes/sec)\n")
        HoneyPotCommand.exit(self)

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.session.input",
            realm="dd",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

    def handle_CTRL_D(self) -> None:
        self.exit()


def parse_size(param: str) -> int:
    """
    Parse dd arguments that indicate block sizes
    Return 0 in case of illegal input
    """
    pattern = r"^(\d+)(c|w|b|kB|K|MB|M|xM|GB|G|T|TB|P|PB|E|EB|Z|ZB|Y|YB)?$"
    z = re.search(pattern, param)
    if not z:
        return 0
    digits = int(z.group(1))
    letters = z.group(2)

    if not letters or letters == "c":
        multiplier = 1
    elif letters == "w":
        multiplier = 2
    elif letters == "b":
        multiplier = 512
    elif letters == "kB":
        multiplier = 1000
    elif letters == "K":
        multiplier = 1024
    elif letters == "MB":
        multiplier = 1000 * 1000
    elif letters == "M" or letters == "xM":
        multiplier = 1024 * 1024
    elif letters == "GB":
        multiplier = 1000 * 1000 * 1000
    elif letters == "G":
        multiplier = 1024 * 1024 * 1024
    else:
        multiplier = 1

    return digits * multiplier


commands["/bin/dd"] = Command_dd
commands["dd"] = Command_dd
