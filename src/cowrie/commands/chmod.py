# Copyright (c) 2020 Peter Sufliarsky <sufliarskyp@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import getopt
import re

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

MODE_REGEX = "^[ugoa]*([-+=]([rwxXst]*|[ugo]))+|[-+=]?[0-7]+$"
TRY_CHMOD_HELP_MSG = "Try 'chmod --help' for more information.\n"


class Command_chmod(HoneyPotCommand):
    def call(self) -> None:
        # parse the command line arguments
        opts, mode, files, getopt_err = self.parse_args()
        if getopt_err:
            return

        # if --help or --version is present, we don't care about the rest
        for o in opts:
            if o == "--help":
                self.write(CHMOD_HELP)
                return
            if o == "--version":
                self.write(CHMOD_VERSION)
                return

        # check for presence of mode and files in arguments
        if (not mode or mode.startswith("-")) and not files:
            self.write("chmod: missing operand\n" + TRY_CHMOD_HELP_MSG)
            return
        if mode and not files:
            self.write(f"chmod: missing operand after ‘{mode}’\n" + TRY_CHMOD_HELP_MSG)
            return

        # mode has to match the regex
        if not re.fullmatch(MODE_REGEX, mode):
            self.write(f"chmod: invalid mode: ‘{mode}’\n" + TRY_CHMOD_HELP_MSG)
            return

        # go through the list of files and check whether they exist
        for file in files:
            if file == "*":
                # if the current directory is empty, return 'No such file or directory'
                files = self.fs.get_path(self.protocol.cwd)[:]
                if not files:
                    self.write("chmod: cannot access '*': No such file or directory\n")
            else:
                path = self.fs.resolve_path(file, self.protocol.cwd)
                if not self.fs.exists(path):
                    self.write(
                        f"chmod: cannot access '{file}': No such file or directory\n"
                    )

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
