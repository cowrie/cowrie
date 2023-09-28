# Copyright (c) 2020 Matej Dujava <mdujava@kocurkovo.cz>
# See the COPYRIGHT file for more information
"""
tee command

"""
from __future__ import annotations


import getopt
import os
from typing import Optional

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}


class Command_tee(HoneyPotCommand):
    """
    tee command
    """

    append = False
    teeFiles: list[str]
    writtenBytes = 0
    ignoreInterupts = False

    def start(self) -> None:
        try:
            optlist, args = getopt.gnu_getopt(
                self.args, "aip", ["help", "append", "version"]
            )
        except getopt.GetoptError as err:
            self.errorWrite(
                f"tee: invalid option -- '{err.opt}'\nTry 'tee --help' for more information.\n"
            )
            self.exit()
            return

        self.teeFiles = []

        for o, _a in optlist:
            if o in ("--help"):
                self.help()
                self.exit()
                return
            elif o in ("-a", "--append"):
                self.append = True
            elif o in ("-a", "--ignore-interrupts"):
                self.ignoreInterupts = True

        for arg in args:
            pname = self.fs.resolve_path(arg, self.protocol.cwd)

            if self.fs.isdir(pname):
                self.errorWrite(f"tee: {arg}: Is a directory\n")
                continue

            try:
                pname = self.fs.resolve_path(arg, self.protocol.cwd)

                folder_path = os.path.dirname(pname)

                if not self.fs.exists(folder_path) or not self.fs.isdir(folder_path):
                    raise FileNotFound

                self.teeFiles.append(pname)
                self.fs.mkfile(pname, 0, 0, 0, 0o644)

            except FileNotFound:
                self.errorWrite(f"tee: {arg}: No such file or directory\n")

        if self.input_data:
            self.output(self.input_data)
            self.exit()

    def write_to_file(self, data: bytes) -> None:
        self.writtenBytes += len(data)
        for outf in self.teeFiles:
            self.fs.update_size(outf, self.writtenBytes)

    def output(self, inb: Optional[bytes]) -> None:
        """
        This is the tee output, if no file supplied
        """
        if inb:
            inp = inb.decode("utf-8")
        else:
            return

        lines = inp.split("\n")
        if lines[-1] == "":
            lines.pop()
        for line in lines:
            self.write(line + "\n")
            self.write_to_file(line.encode("utf-8") + b"\n")

    def lineReceived(self, line: str) -> None:
        """
        This function logs standard input from the user send to tee
        """
        log.msg(
            eventid="cowrie.session.input",
            realm="tee",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )

        self.output(line.encode("utf-8"))

    def handle_CTRL_C(self) -> None:
        if not self.ignoreInterupts:
            log.msg("Received CTRL-C, exiting..")
            self.write("^C\n")
            self.exit()

    def handle_CTRL_D(self) -> None:
        """
        ctrl-d is end-of-file, time to terminate
        """
        self.exit()

    def help(self) -> None:
        self.write(
            """Usage: tee [OPTION]... [FILE]...
Copy standard input to each FILE, and also to standard output.

  -a, --append              append to the given FILEs, do not overwrite
  -i, --ignore-interrupts   ignore interrupt signals
  -p                        diagnose errors writing to non pipes
      --output-error[=MODE]   set behavior on write error.  See MODE below
      --help     display this help and exit
      --version  output version information and exit

MODE determines behavior with write errors on the outputs:
  'warn'         diagnose errors writing to any output
  'warn-nopipe'  diagnose errors writing to any output not a pipe
  'exit'         exit on error writing to any output
  'exit-nopipe'  exit on error writing to any output not a pipe
The default MODE for the -p option is 'warn-nopipe'.
The default operation when --output-error is not specified, is to
exit immediately on error writing to a pipe, and diagnose errors
writing to non pipe outputs.

GNU coreutils online help: <https://www.gnu.org/software/coreutils/>
Full documentation <https://www.gnu.org/software/coreutils/tee>
or available locally via: info '(coreutils) tee invocation'
"""
        )


commands["/bin/tee"] = Command_tee
commands["tee"] = Command_tee
