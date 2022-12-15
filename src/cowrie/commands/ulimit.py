# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.

"""
This module ...
"""

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_ulimit(HoneyPotCommand):
    """
    ulimit

    ulimit: usage: ulimit [-SHacdfilmnpqstuvx] [limit]
    """

    def call(self) -> None:
        # Parse options or display no files
        try:
            opts, args = getopt.getopt(self.args, "SHacdfilmnpqstuvx")
        except getopt.GetoptError as err:
            self.errorWrite(f"-bash: ulimit: {err}\n")
            self.write("ulimit: usage: ulimit [-SHacdfilmnpqstuvx] [limit]\n")
            return

        # Parse options
        for o, a in opts:
            if o in ("-c"):
                self.do_ulimit(key="core", value=int(a))
                return
            elif o in ("-a"):
                self.do_ulimit(key="all")
                return
        self.do_ulimit()

    def do_ulimit(self, key: str = "core", value: int = 0) -> None:
        pass


commands["ulimit"] = Command_ulimit
