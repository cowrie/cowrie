# Copyright (c) 2014 Peter Reuterås <peter@reuteras.com>
# See the COPYRIGHT file for more information


from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_nohup(HoneyPotCommand):
    def call(self) -> None:
        if not len(self.args):
            self.write("nohup: missing operand\n")
            self.write("Try `nohup --help' for more information.\n")
            return
        path = self.fs.resolve_path("nohup.out", self.protocol.cwd)
        if self.fs.exists(path):
            return
        self.fs.mkfile(path, self.protocol.user.uid, self.protocol.user.gid, 0, 33188)
        self.write("nohup: ignoring input and appending output to 'nohup.out'\n")


commands["/usr/bin/nohup"] = Command_nohup
commands["nohup"] = Command_nohup
