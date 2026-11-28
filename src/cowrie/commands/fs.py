# SPDX-FileCopyrightText: 2009-2011 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


"""
Filesystem related commands
"""

from __future__ import annotations

import copy
import getopt
import posixpath
from typing import TYPE_CHECKING

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_cd(HoneyPotCommand):
    """
    cd command
    """

    def call(self) -> None:
        if not self.args or self.args[0] == "~":
            pname = self.user["home"]
        else:
            pname = self.args[0]
        newpath = ""
        try:
            newpath = self.fs.resolve_path(pname, self.cwd)
            inode = self.fs.getfile(newpath)
        except Exception:
            inode = None
        if pname == "-":
            self.errorWrite(f"{self.shell.error_prefix()}cd: OLDPWD not set\n")
            self.exit_code = 1
            return
        if inode is None or inode is False:
            self.errorWrite(
                f"{self.shell.error_prefix()}cd: {pname}: No such file or directory\n"
            )
            self.exit_code = 1
            return
        if inode[fs.A_TYPE] != fs.T_DIR:
            self.errorWrite(
                f"{self.shell.error_prefix()}cd: {pname}: Not a directory\n"
            )
            self.exit_code = 1
            return
        # cd is a builtin: it changes the running shell's directory, not this
        # command process's own.
        self.shell.cwd = newpath


commands["cd"] = Command_cd


def _target_reason(command: HoneyPotCommand, dest: str) -> str:
    """Why the target of a multi-file cp or mv is no directory, as coreutils
    words it: a file is there, or nothing is."""
    path = command.fs.resolve_path(dest, command.cwd)
    return "Not a directory" if command.fs.exists(path) else "No such file or directory"


class Command_cp(HoneyPotCommand):
    """
    cp command
    """

    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("cp: missing file operand\n")
            self.errorWrite("Try 'cp --help' for more information.\n")
            self.exit_code = 1
            return
        try:
            optlist, args = getopt.gnu_getopt(self.args, "-abdfiHlLPpRrsStTuvx")
        except getopt.GetoptError:
            self.errorWrite("Unrecognized option\n")
            self.exit_code = 1
            return
        recursive = False
        for opt in optlist:
            if opt[0] in ("-r", "-a", "-R"):
                recursive = True

        def resolv(pname: str) -> str:
            rsv: str = self.fs.resolve_path(pname, self.cwd)
            return rsv

        if len(args) < 2:
            self.errorWrite(
                f"cp: missing destination file operand after '{self.args[0]}'\n"
            )
            self.errorWrite("Try 'cp --help' for more information.\n")
            self.exit_code = 1
            return
        sources, dest = args[:-1], args[-1]
        # Quoting reaches the command as an empty argument; there is no such
        # path, so there is nothing to resolve or index into.
        if not dest:
            self.errorWrite(
                f"cp: cannot create regular file '{dest}': No such file or directory\n"
            )
            self.exit_code = 1
            return
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.errorWrite(f"cp: target '{dest}': {_target_reason(self, dest)}\n")
            self.exit_code = 1
            return

        if dest[-1] == "/" and not self.fs.exists(resolv(dest)) and not recursive:
            self.errorWrite(
                f"cp: cannot create regular file '{dest}': Is a directory\n"
            )
            self.exit_code = 1
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = posixpath.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.errorWrite(
                    "cp: cannot create regular file "
                    + f"'{dest}': No such file or directory\n"
                )
                self.exit_code = 1
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.errorWrite(f"cp: cannot stat '{src}': No such file or directory\n")
                self.exit_code = 1
                continue
            if not recursive and self.fs.isdir(resolv(src)):
                self.errorWrite(f"cp: -r not specified; omitting directory '{src}'\n")
                self.exit_code = 1
                continue
            s = copy.deepcopy(self.fs.getfile(resolv(src)))
            if isdir:
                destdir = resolv(dest)
                outfile = posixpath.basename(src)
            else:
                destdir = posixpath.dirname(resolv(dest))
                outfile = posixpath.basename(dest.rstrip("/"))
            s[fs.A_NAME] = outfile
            self.fs.link_entry(s, destdir)


commands["/bin/cp"] = Command_cp
commands["cp"] = Command_cp


class Command_mv(HoneyPotCommand):
    """
    mv command
    """

    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("mv: missing file operand\n")
            self.errorWrite("Try 'mv --help' for more information.\n")
            self.exit_code = 1
            return

        try:
            _optlist, args = getopt.gnu_getopt(self.args, "-bfiStTuv")
        except getopt.GetoptError:
            self.errorWrite("Unrecognized option\n")
            self.exit_code = 1
            return

        def resolv(pname: str) -> str:
            rsv: str = self.fs.resolve_path(pname, self.cwd)
            return rsv

        if len(args) < 2:
            self.errorWrite(
                f"mv: missing destination file operand after '{self.args[0]}'\n"
            )
            self.errorWrite("Try 'mv --help' for more information.\n")
            self.exit_code = 1
            return
        sources, dest = args[:-1], args[-1]
        # Quoting reaches the command as an empty argument; there is no such
        # path, so there is nothing to resolve or index into.
        if not dest:
            self.errorWrite(
                f"mv: cannot move '{sources[0]}' to '{dest}': "
                "No such file or directory\n"
            )
            self.exit_code = 1
            return
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.errorWrite(f"mv: target '{dest}': {_target_reason(self, dest)}\n")
            self.exit_code = 1
            return

        if dest[-1] == "/" and not self.fs.exists(resolv(dest)) and len(sources) != 1:
            self.errorWrite(
                f"mv: cannot create regular file '{dest}': Is a directory\n"
            )
            self.exit_code = 1
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = posixpath.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.errorWrite(
                    f"mv: cannot move '{sources[0]}' to '{dest}': "
                    "No such file or directory\n"
                )
                self.exit_code = 1
                return

        for src in sources:
            srcpath = resolv(src)
            if not self.fs.exists(srcpath):
                self.errorWrite(f"mv: cannot stat '{src}': No such file or directory\n")
                self.exit_code = 1
                continue
            if isdir:
                destpath = posixpath.join(resolv(dest), posixpath.basename(src))
            else:
                destpath = resolv(dest)
            self.fs.rename(srcpath, destpath)


commands["/bin/mv"] = Command_mv
commands["mv"] = Command_mv


class Command_pwd(HoneyPotCommand):
    """
    pwd command
    """

    def call(self) -> None:
        self.write(self.cwd + "\n")


commands["/bin/pwd"] = Command_pwd
commands["pwd"] = Command_pwd


class Command_touch(HoneyPotCommand):
    """
    touch command
    """

    def call(self) -> None:
        if not len(self.args):
            self.errorWrite("touch: missing file operand\n")
            self.errorWrite("Try 'touch --help' for more information.\n")
            self.exit_code = 1
            return
        for f in self.args:
            pname = self.fs.resolve_path(f, self.cwd)
            if not self.fs.exists(posixpath.dirname(pname)):
                self.errorWrite(
                    f"touch: cannot touch '{f}': No such file or directory\n"
                )
                self.exit_code = 1
                continue
            if self.fs.exists(pname):
                # FIXME: modify the timestamp here
                continue
            # can't touch in special directories
            if any([pname.startswith(_p) for _p in fs.SPECIAL_PATHS]):
                self.errorWrite(f"touch: cannot touch '{f}': Permission denied\n")
                self.exit_code = 1
                continue

            self.fs.mkfile(pname, self.user["uid"], self.user["gid"], 0, 33188)


commands["/bin/touch"] = Command_touch
commands["touch"] = Command_touch
commands[">"] = Command_touch
