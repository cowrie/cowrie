# SPDX-FileCopyrightText: 2009-2011 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import posixpath
import re
import stat
from typing import TYPE_CHECKING

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_mkdir(HoneyPotCommand):
    """
    mkdir command
    """

    verbose: bool = False

    def call(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(
                self.args, "m:pv", ["mode=", "parents", "verbose"]
            )
        except getopt.GetoptError as err:
            self.errorWrite(f"mkdir: invalid option -- '{err.opt}'\n")
            self.errorWrite("Try 'mkdir --help' for more information.\n")
            self.exit_code = 1
            return
        parents = False
        mode = 0o755
        for opt, arg in optlist:
            if opt in ("-p", "--parents"):
                parents = True
            elif opt in ("-v", "--verbose"):
                self.verbose = True
            elif opt in ("-m", "--mode"):
                # Only octal modes are understood, not symbolic ones like u+x.
                if not re.fullmatch("[0-7]{1,4}", arg):
                    self.errorWrite(f"mkdir: invalid mode '{arg}'\n")
                    self.exit_code = 1
                    return
                mode = int(arg, 8)
        if not args:
            self.errorWrite("mkdir: missing operand\n")
            self.errorWrite("Try 'mkdir --help' for more information.\n")
            self.exit_code = 1
            return
        for f in args:
            if parents:
                self.make_with_parents(f, mode)
            else:
                self.make_directory(f, mode)

    def fail(self, name: str, reason: str) -> bool:
        self.errorWrite(f"mkdir: cannot create directory '{name}': {reason}\n")
        self.exit_code = 1
        return False

    def make_directory(self, name: str, mode: int) -> bool:
        """Create one directory, reporting failure. Returns True on success."""
        path = self.fs.resolve_path(name, self.cwd)
        if self.fs.exists(path):
            return self.fail(name, "File exists")
        try:
            self.fs.mkdir(
                path, self.user["uid"], self.user["gid"], 4096, stat.S_IFDIR | mode
            )
        except OSError as e:
            return self.fail(name, f"{e.strerror}")
        if self.verbose:
            self.write(f"mkdir: created directory '{name}'\n")
        return True

    def make_with_parents(self, name: str, mode: int) -> None:
        """mkdir -p: create each missing directory along the path; existing
        directories are not an error. The mode applies to the last one only."""
        parts = [part for part in name.split("/") if part]
        prefix = "/" if name.startswith("/") else ""
        for i, part in enumerate(parts):
            prefix = posixpath.join(prefix, part)
            last = i == len(parts) - 1
            path = self.fs.resolve_path(prefix, self.cwd)
            if self.fs.isdir(path):
                continue
            if self.fs.exists(path):
                self.fail(prefix, "File exists" if last else "Not a directory")
                return
            if not self.make_directory(prefix, mode if last else 0o755):
                return


commands["/bin/mkdir"] = Command_mkdir
commands["mkdir"] = Command_mkdir


class Command_rmdir(HoneyPotCommand):
    """
    rmdir command
    """

    def call(self) -> None:
        if not self.args:
            self.errorWrite("rmdir: missing operand\n")
            self.errorWrite("Try 'rmdir --help' for more information.\n")
            self.exit_code = 1
            return
        for f in self.args:
            pname = self.fs.resolve_path(f, self.cwd)
            try:
                if len(self.fs.get_path(pname)):
                    self.errorWrite(
                        f"rmdir: failed to remove '{f}': Directory not empty\n"
                    )
                    self.exit_code = 1
                    continue
                directory = self.fs.get_path("/".join(pname.split("/")[:-1]))
            except (IndexError, fs.FileNotFound):
                directory = None
            fname = posixpath.basename(f)
            if not directory or fname not in [x[fs.A_NAME] for x in directory]:
                self.errorWrite(
                    f"rmdir: failed to remove '{f}': No such file or directory\n"
                )
                self.exit_code = 1
                continue
            for i in directory[:]:
                if i[fs.A_NAME] == fname:
                    if i[fs.A_TYPE] != fs.T_DIR:
                        self.errorWrite(
                            f"rmdir: failed to remove '{f}': Not a directory\n"
                        )
                        self.exit_code = 1
                        continue
                    directory.remove(i)
                    break


commands["/bin/rmdir"] = Command_rmdir
commands["rmdir"] = Command_rmdir
