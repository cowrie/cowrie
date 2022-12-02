# Copyright (c) 2018 Danilo Vargas <danilo.vargas@csiete.org>
# See the COPYRIGHT file for more information

from __future__ import annotations

import os

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_NAME

commands = {}


class Command_du(HoneyPotCommand):
    def message_help(self) -> str:
        return """Usage: du [OPTION]... [FILE]...
  or:  du [OPTION]... --files0-from=F
Summarize disk usage of the set of FILEs, recursively for directories.

Mandatory arguments to long options are mandatory for short options too.
  -0, --null            end each output line with NUL, not newline
  -a, --all             write counts for all files, not just directories
      --apparent-size   print apparent sizes, rather than disk usage; although
                          the apparent size is usually smaller, it may be
                          larger due to holes in ('sparse') files, internal
                          fragmentation, indirect blocks, and the like
  -B, --block-size=SIZE  scale sizes by SIZE before printing them; e.g.,
                           '-BM' prints sizes in units of 1,048,576 bytes;
                           see SIZE format below
  -b, --bytes           equivalent to '--apparent-size --block-size=1'
  -c, --total           produce a grand total
  -D, --dereference-args  dereference only symlinks that are listed on the
                          command line
  -d, --max-depth=N     print the total for a directory (or file, with --all)
                          only if it is N or fewer levels below the command
                          line argument;  --max-depth=0 is the same as
                          --summarize
      --files0-from=F   summarize disk usage of the
                          NUL-terminated file names specified in file F;
                          if F is -, then read names from standard input
  -H                    equivalent to --dereference-args (-D)
  -h, --human-readable  print sizes in human readable format (e.g., 1K 234M 2G)
      --inodes          list inode usage information instead of block usage
  -k                    like --block-size=1K
  -L, --dereference     dereference all symbolic links
  -l, --count-links     count sizes many times if hard linked
  -m                    like --block-size=1M
  -P, --no-dereference  don't follow any symbolic links (this is the default)
  -S, --separate-dirs   for directories do not include size of subdirectories
      --si              like -h, but use powers of 1000 not 1024
  -s, --summarize       display only a total for each argument
  -t, --threshold=SIZE  exclude entries smaller than SIZE if positive,
                          or entries greater than SIZE if negative
      --time            show time of the last modification of any file in the
                          directory, or any of its subdirectories
      --time=WORD       show time as WORD instead of modification time:
                          atime, access, use, ctime or status
      --time-style=STYLE  show times using STYLE, which can be:
                            full-iso, long-iso, iso, or +FORMAT;
                            FORMAT is interpreted like in 'date'
  -X, --exclude-from=FILE  exclude files that match any pattern in FILE
      --exclude=PATTERN    exclude files that match PATTERN
  -x, --one-file-system    skip directories on different file systems
      --help     display this help and exit
      --version  output version information and exit

Display values are in units of the first available SIZE from --block-size,
and the DU_BLOCK_SIZE, BLOCK_SIZE and BLOCKSIZE environment variables.
Otherwise, units default to 1024 bytes (or 512 if POSIXLY_CORRECT is set).

The SIZE argument is an integer and optional unit (example: 10K is 10*1024).
Units are K,M,G,T,P,E,Z,Y (powers of 1024) or KB,MB,... (powers of 1000).

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Report du translation bugs to <http://translationproject.org/team/>
Full documentation at: <http://www.gnu.org/software/coreutils/du>
or available locally via: info '(coreutils) du invocation'\n"""

    def call(self) -> None:
        self.showHidden = False
        self.showDirectories = False
        path = self.protocol.cwd
        args = self.args
        if args:
            if "-sh" == args[0]:
                self.write("28K     .\n")
            elif "--help" == args[0]:
                self.write(self.message_help())
            else:
                self.du_show(path)
        else:
            self.du_show(path, all=True)

    def du_show(self, path: str, all: bool = False) -> None:
        try:
            if self.protocol.fs.isdir(path) and not self.showDirectories:
                files = self.protocol.fs.get_path(path)[:]
                if self.showHidden:
                    dot = self.protocol.fs.getfile(path)[:]
                    dot[A_NAME] = "."
                    files.append(dot)
                    # FIXME: should grab dotdot off the parent instead
                    dotdot = self.protocol.fs.getfile(path)[:]
                    dotdot[A_NAME] = ".."
                    files.append(dotdot)
                else:
                    files = [x for x in files if not x[A_NAME].startswith(".")]
                files.sort()
            else:
                files = (self.protocol.fs.getfile(path)[:],)
        except Exception:
            self.write(f"ls: cannot access {path}: No such file or directory\n")
            return

        filenames = [x[A_NAME] for x in files]
        if not filenames:
            return
        for filename in filenames:
            if all:
                isdir = self.protocol.fs.isdir(os.path.join(path, filename))
                if isdir:
                    filename = f"4       ./{filename}\n"
                    self.write(filename)
            else:
                filename = f"4       {filename}\n"
                self.write(filename)
        if all:
            self.write("36      .\n")


commands["du"] = Command_du
