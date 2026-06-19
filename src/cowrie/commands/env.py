# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}

"""
env: invalid option -- 'h'
Try `env --help' for more information.

Usage: env [OPTION]... [-] [NAME=VALUE]... [COMMAND [ARG]...]
Set each NAME to VALUE in the environment and run COMMAND.

  -i, --ignore-environment  start with an empty environment
  -0, --null           end each output line with 0 byte rather than newline
  -u, --unset=NAME     remove variable from the environment
      --help     display this help and exit
      --version  output version information and exit

A mere - implies -i.  If no COMMAND, print the resulting environment.

Report env bugs to bug-coreutils@gnu.org
GNU coreutils home page: <http://www.gnu.org/software/coreutils/>
General help using GNU software: <http://www.gnu.org/gethelp/>
For complete documentation, run: info coreutils 'env invocation'
"""


class Command_env(HoneyPotCommand):
    def call(self) -> None:
        # env shows only exported variables, not plain shell variables
        for name in self.environ:
            if name in self.exported:
                self.write(f"{name}={self.environ[name]}\n")


commands["/usr/bin/env"] = Command_env
commands["env"] = Command_env
