# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.

"""
This module contains the sleep command
"""

from __future__ import annotations

import getopt
import re

from cowrie.shell.command import HoneyPotCommand
from twisted.internet import reactor

commands = {}


class Command_sleep(HoneyPotCommand):
    """
    Sleep
    """

    pattern = re.compile(r"(\d+)[mhs]?")

    def print_usage_error(self, error_msg: str = "") -> None:
        """Print usage error message"""
        if error_msg:
            self.errorWrite(f"sleep: {error_msg}\n")
        self.errorWrite("Try 'sleep --help' for more information.\n")

    def print_help_message(self) -> None:
        self.write("""
Usage: sleep NUMBER[SUFFIX]...
  or:  sleep OPTION
Pause for NUMBER seconds.  SUFFIX may be 's' for seconds (the default),
'm' for minutes, 'h' for hours or 'd' for days.  NUMBER need not be an
integer.  Given two or more arguments, pause for the amount of time
specified by the sum of their values.

      --help        display this help and exit
      --version     output version information and exit

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation <https://www.gnu.org/software/coreutils/sleep>
""")

    def print_version(self) -> None:
        self.write("""
sleep (GNU coreutils) 8.3
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Jim Meyering and Paul Eggert.
""")

    def done(self) -> None:
        self.exit()

    def start(self) -> None:
        try:
            optlist, arglist = getopt.getopt(self.args, "", ["help", "version"])
        except getopt.GetoptError as err:
            # Check if the error was caused by a long option (--option)
            if f"--{err.opt}" in self.args:
                message = "unrecognized option"
            else:
                # Short options (-o) are not supported
                message = "invalid option --"

            self.print_usage_error(f"{message} '{err.opt}'")
            self.exit()
            return

        # Handle help option first - print help and exit immediately
        if "--help" in [o[0] for o in optlist]:
            self.print_help_message()
            self.exit()
            return

        # Handle version option then - print version and exit immediately
        if "--version" in [o[0] for o in optlist]:
            self.print_version()
            self.exit()
            return

        # Handle no arguments
        if not arglist:
            self.print_usage_error("missing operand")
            self.exit()
            return

        if len(self.args) == 1:
            m = re.match(r"(\d+)[mhs]?", self.args[0])
            if m:
                _time = int(m.group(1))
                # Always sleep in seconds, not minutes or hours
                self.scheduled = reactor.callLater(_time, self.done)  # type: ignore[attr-defined]
            else:
                self.write("usage: sleep seconds\n")
                self.exit()
        else:
            self.write("usage: sleep seconds\n")
            self.exit()


commands["/bin/sleep"] = Command_sleep
commands["sleep"] = Command_sleep
