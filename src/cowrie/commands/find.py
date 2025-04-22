# Copyright (c) 2010 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information
# Contributor: Onder7994

"""
find command
"""

from __future__ import annotations
from cowrie.shell.command import HoneyPotCommand
import fnmatch
import os

commands = {}

class Command_find(HoneyPotCommand):
    """
    find command
    """

    def start(self) -> None:
        self.maxdepth: int = 20
        self.name_pattern = None
        self.type_filter = None

        self.start_path = self.protocol.cwd

        idx = 0
        while idx < len(self.args):
            arg = self.args[idx]

            if arg == "-name":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-name`\n")
                    self.exit()
                    return
                self.name_pattern = self.args[idx]

            elif arg == "-type":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-type`\n")
                    self.exit()
                    return
                val = self.args[idx]
                if val in ("f", "d"):
                    self.type_filter = val
                else:
                    self.errorWrite("find: unknown argument to -type. Use 'f' or 'd'\n")
                    self.exit()
                    return

            elif arg == "-maxdepth":
                idx += 1
                if idx >= len(self.args):
                    self.errorWrite("find: missing argument to `-maxdepth`\n")
                    self.exit()
                    return
                try:
                    self.maxdepth = int(self.args[idx])
                except ValueError:
                    self.errorWrite("find: maxdepth must be an integer\n")
                    self.exit()
                    return

            elif not arg.startswith("-") and self.start_path == self.protocol.cwd:
                self.start_path = self.fs.resolve_path(arg, self.protocol.cwd)

            else:
                self.errorWrite(f"find: unknown argument '{arg}'\n")
                self.exit()
                return

            idx += 1

        self.find_recursive(self.start_path, 0)
        self.exit()

    def find_recursive(self, path: str, depth: int) -> None:
        if self.maxdepth is not None and depth > self.maxdepth:
            return
        try:
            if not self.fs.exists(path):
                return
            if self._match(path):
                self.write(f"{path}\n")

            if self.fs.isdir(path):
                for entry in self.fs.listdir(path):
                    if entry in (".", ".."):
                        continue
                    full_path = os.path.join(path, entry)
                    self.find_recursive(full_path, depth + 1)
        except Exception as e:
            self.errorWrite(f"find: error accessing {path}: {e}\n")

    def _match(self, path: str) -> bool:
        basename = os.path.basename(path)

        if self.name_pattern and not fnmatch.fnmatch(basename, self.name_pattern):
            return False

        if self.type_filter == "f" and not self.fs.isfile(path):
            return False
        if self.type_filter == "d" and not self.fs.isdir(path):
            return False

        return True


commands["find"] = Command_find
commands["/bin/find"] = Command_find