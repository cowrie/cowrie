# SPDX-FileCopyrightText: 2014 Peter Reuterås <peter@reuteras.com>
# SPDX-FileCopyrightText: 2015-2024 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_nohup(HoneyPotCommand):
    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("nohup: missing operand\n")
            self.errorWrite("Try `nohup --help' for more information.\n")
            # nohup's own failures exit 125, apart from its command's status.
            self.exit_code = 125
            return
        path = self.fs.resolve_path("nohup.out", self.cwd)
        if self.fs.exists(path):
            return
        self.fs.mkfile(path, self.user["uid"], self.user["gid"], 0, 33188)
        self.write("nohup: ignoring input and appending output to 'nohup.out'\n")


commands["/usr/bin/nohup"] = Command_nohup
commands["nohup"] = Command_nohup
