# SPDX-FileCopyrightText: 2020 Peter Šufliarsky
# SPDX-FileCopyrightText: 2020 Peter Sufliarsky <sufliarskyp@gmail.com>
# SPDX-FileCopyrightText: 2021-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Emulates GNU chmod: parses octal and symbolic modes and applies them
# ABOUTME: to the emulated filesystem through fs.chmod.

from __future__ import annotations

import getopt
import re
import stat

from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

commands = {}

CHMOD_HELP = """Usage: chmod [OPTION]... MODE[,MODE]... FILE...
  or:  chmod [OPTION]... OCTAL-MODE FILE...
  or:  chmod [OPTION]... --reference=RFILE FILE...
Change the mode of each FILE to MODE.
With --reference, change the mode of each FILE to that of RFILE.

  -c, --changes          like verbose but report only when a change is made
  -f, --silent, --quiet  suppress most error messages
  -v, --verbose          output a diagnostic for every file processed
      --no-preserve-root  do not treat '/' specially (the default)
      --preserve-root    fail to operate recursively on '/'
      --reference=RFILE  use RFILE's mode instead of MODE values
  -R, --recursive        change files and directories recursively
      --help     display this help and exit
      --version  output version information and exit

Each MODE is of the form '[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=][0-7]+'.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation at: <https://www.gnu.org/software/coreutils/chmod>
or available locally via: info '(coreutils) chmod invocation'
"""

CHMOD_VERSION = """chmod (GNU coreutils) 8.25
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by David MacKenzie and Jim Meyering.
"""

MODE_CLAUSE = r"[ugoa]*(?:[-+=](?:[rwxXst]*|[ugo]))+|[-+=][0-7]+"
MODE_REGEX = rf"[0-7]+|(?:{MODE_CLAUSE})(?:,(?:{MODE_CLAUSE}))*"
TRY_CHMOD_HELP_MSG = "Try 'chmod --help' for more information.\n"

# The emulated shell's umask. A clause without u/g/o/a leaves these bits alone.
UMASK = 0o022

# Bits each class letter selects; the special bit sits with the class it modifies.
WHO_BITS = {
    "u": stat.S_ISUID | stat.S_IRWXU,
    "g": stat.S_ISGID | stat.S_IRWXG,
    "o": stat.S_ISVTX | stat.S_IRWXO,
    "a": 0o7777,
}

# Position of each class's rwx triplet, for copying one class to others (u=g).
CLASS_SHIFT = {"u": 6, "g": 3, "o": 0}

# Bits each permission letter sets, before masking by the affected classes.
PERM_BITS = {
    "r": 0o444,
    "w": 0o222,
    "x": 0o111,
    "s": stat.S_ISUID | stat.S_ISGID,
    "t": stat.S_ISVTX,
}


def apply_mode(spec: str, mode: int, is_dir: bool, umask: int = UMASK) -> int:
    """Return the permission bits that GNU chmod's ``spec`` gives a file whose
    permission bits are ``mode``. ``spec`` must already match MODE_REGEX."""
    if spec.isdigit():
        return int(spec, 8)
    for clause in spec.split(","):
        who = 0
        i = 0
        while clause[i] in WHO_BITS:
            who |= WHO_BITS[clause[i]]
            i += 1
        while i < len(clause):
            op = clause[i]
            i += 1
            end = i
            while end < len(clause) and clause[end] not in "-+=":
                end += 1
            perms = clause[i:end]
            i = end
            if perms.isdigit():
                # An octal operand names every bit explicitly; no umask applies.
                affected = 0o7777
                value = int(perms, 8)
            else:
                affected = who or 0o7777 & ~umask
                value = 0
                for letter in perms:
                    if letter in "ugo":
                        value |= ((mode >> CLASS_SHIFT[letter]) & 0o7) * 0o111
                    elif letter == "X":
                        if is_dir or mode & 0o111:
                            value |= 0o111
                    else:
                        value |= PERM_BITS[letter]
            change = value & affected
            if op == "=":
                mode = (mode & ~affected) | change
            elif op == "+":
                mode |= change
            else:
                mode &= ~change
    return mode


class Command_chmod(HoneyPotCommand):
    def call(self) -> None:
        # parse the command line arguments
        opts, mode, files, getopt_err = self.parse_args()
        if getopt_err:
            return

        # if --help or --version is present, we don't care about the rest
        for o, _ in opts:
            if o == "--help":
                self.errorWrite(CHMOD_HELP)
                return
            if o == "--version":
                self.errorWrite(CHMOD_VERSION)
                return

        # check for presence of mode and files in arguments
        if (not mode or mode.startswith("-")) and not files:
            self.errorWrite("chmod: missing operand\n" + TRY_CHMOD_HELP_MSG)
            return
        if mode and not files:
            self.errorWrite(
                f"chmod: missing operand after ‘{mode}’\n" + TRY_CHMOD_HELP_MSG
            )
            return

        # mode has to match the regex and fit in the permission bits
        if not re.fullmatch(MODE_REGEX, mode) or (
            mode.isdigit() and int(mode, 8) > 0o7777
        ):
            self.errorWrite(f"chmod: invalid mode: ‘{mode}’\n" + TRY_CHMOD_HELP_MSG)
            return

        # go through the list of files and check whether they exist
        for file in files:
            if file == "*":
                # the shell leaves globbing to commands; * names the visible entries
                names = [
                    entry[fs.A_NAME]
                    for entry in self.fs.get_path(self.cwd)
                    if not entry[fs.A_NAME].startswith(".")
                ]
                # if the current directory is empty, return 'No such file or directory'
                if not names:
                    self.errorWrite(
                        "chmod: cannot access '*': No such file or directory\n"
                    )
                for name in names:
                    self.change_mode(name, mode)
            else:
                path = self.fs.resolve_path(file, self.cwd)
                if not self.fs.exists(path):
                    self.errorWrite(
                        f"chmod: cannot access '{file}': No such file or directory\n"
                    )
                else:
                    self.change_mode(file, mode)

    def change_mode(self, file: str, mode: str) -> None:
        """Apply ``mode`` to ``file``, warning like GNU chmod when the umask
        kept the result from matching what the mode asked for."""
        path = self.fs.resolve_path(file, self.cwd)
        node = self.fs.getfile(path)
        if node is None:
            return
        current = stat.S_IMODE(node[fs.A_MODE])
        is_dir = self.fs.isdir(path)
        new = apply_mode(mode, current, is_dir)
        self.fs.chmod(path, new)
        expected = apply_mode(mode, current, is_dir, umask=0)
        if new != expected:
            self.errorWrite(
                f"chmod: {file}: new permissions are {stat.filemode(new)[1:]}, "
                f"not {stat.filemode(expected)[1:]}\n"
            )
            self.exit_code = 1

    def parse_args(self):
        mode = None

        # a mode specification starting with '-' would cause the getopt parser to throw an error
        # therefore, remove the first such argument self.args before parsing with getopt
        args_new = []
        for arg in self.args:
            if not mode and arg.startswith("-") and re.fullmatch(MODE_REGEX, arg):
                mode = arg
            else:
                args_new.append(arg)

        # parse the command line options with getopt
        try:
            opts, args = getopt.gnu_getopt(
                args_new,
                "cfvR",
                [
                    "changes",
                    "silent",
                    "quiet",
                    "verbose",
                    "no-preserve-root",
                    "preserve-root",
                    "reference=",
                    "recursive",
                    "help",
                    "version",
                ],
            )
        except getopt.GetoptError as err:
            failed_opt = err.msg.split(" ")[1]
            if failed_opt.startswith("--"):
                self.errorWrite(
                    f"chmod: unrecognized option '--{err.opt}'\n" + TRY_CHMOD_HELP_MSG
                )
            else:
                self.errorWrite(
                    f"chmod: invalid option -- '{err.opt}'\n" + TRY_CHMOD_HELP_MSG
                )
            return [], None, [], True

        # if mode was not found before, use the first arg as mode
        if not mode and len(args) > 0:
            mode = args.pop(0)

        # the rest of args should be files
        files = args

        return opts, mode, files, False


commands["/bin/chmod"] = Command_chmod
commands["chmod"] = Command_chmod
