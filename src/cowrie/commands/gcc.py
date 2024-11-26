# Copyright (c) 2013 Bas Stottelaar <basstottelaar [AT] gmail [DOT] com>

from __future__ import annotations

import getopt
import os
import random
import re
import time

from twisted.internet import reactor

from cowrie.core.config import CowrieConfig
from cowrie.shell.command import HoneyPotCommand
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from twisted.internet.defer import Deferred

commands = {}


class Command_gcc(HoneyPotCommand):
    # Name of program. Under OSX, you might consider i686-apple-darwin11-llvm-gcc-X.X
    APP_NAME = "gcc"

    # GCC verson, used in help, version and the commandline name gcc-X.X
    APP_VERSION = (4, 7, 2)

    # Random binary data, which looks awesome. You could change this to whatever you want, but this
    # data will be put in the actual file and thus exposed to our hacker when he\she cats the file.
    RANDOM_DATA = (
        b"\x6a\x00\x48\x89\xe5\x48\x83\xe4\xf0\x48\x8b\x7d\x08\x48\x8d\x75\x10\x89\xfa"
        b"\x83\xc2\x01\xc1\xe2\x03\x48\x01\xf2\x48\x89\xd1\xeb\x04\x48\x83\xc1\x08\x48"
        b"\x83\x39\x00\x75\xf6\x48\x83\xc1\x08\xe8\x0c\x00\x00\x00\x89\xc7\xe8\xb9\x00"
        b"\x00\x00\xf4\x90\x90\x90\x90\x55\x48\x89\xe5\x48\x83\xec\x40\x89\x7d\xfc\x48"
        b"\x89\x75\xf0\x48\x8b\x45\xf0\x48\x8b\x00\x48\x83\xf8\x00\x75\x0c\xb8\x00\x00"
        b"\x00\x00\x89\xc7\xe8\x8c\x00\x00\x00\x48\x8b\x45\xf0\x48\x8b\x40\x08\x30\xc9"
        b"\x48\x89\xc7\x88\xc8\xe8\x7e\x00\x00\x00\x89\xc1\x89\x4d\xdc\x48\x8d\x0d\xd8"
        b"\x01\x00\x00\x48\x89\xcf\x48\x89\x4d\xd0\xe8\x72\x00\x00\x00\x8b\x4d\xdc\x30"
        b"\xd2\x48\x8d\x3d\xa4\x00\x00\x00\x89\xce\x88\x55\xcf\x48\x89\xc2\x8a\x45\xcf"
        b"\xe8\x53\x00\x00\x00\x8b\x45\xdc\x88\x05\xc3\x01\x00\x00\x8b\x45\xdc\xc1\xe8"
        b"\x08\x88\x05\xb8\x01\x00\x00\x8b\x45\xdc\xc1\xe8\x10\x88\x05\xad\x01\x00\x00"
        b"\x8b\x45\xdc\xc1\xe8\x18\x88\x05\xa2\x01\x00\x00\x48\x8b\x45\xd0\x48\x89\x45"
        b"\xe0\x48\x8b\x45\xe0\xff\xd0\x8b\x45\xec\x48\x83\xc4\x40\x5d\xc3\xff\x25\x3e"
        b"\x01\x00\x00\xff\x25\x40\x01\x00\x00\xff\x25\x42\x01\x00\x00\xff\x25\x44\x01"
        b"\x00\x00\x4c\x8d\x1d\x1d\x01\x00\x00\x41\x53\xff\x25\x0d\x01\x00\x00\x90\x68"
        b"\x00\x00\x00\x00\xe9\xe6\xff\xff\xff\x68\x0c\x00\x00\x00\xe9\xdc\xff\xff\xff"
        b"\x68\x1d\x00\x00\x00\xe9\xd2\xff\xff\xff\x68\x2b\x00\x00\x00\xe9\xc8\xff\xff"
        b"\xff\x01\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x00\x00"
        b"\x00\x00\x1c\x00\x00\x00\x02\x00\x00\x00\x00\x0e\x00\x00\x34\x00\x00\x00\x34"
        b"\x00\x00\x00\xf5\x0e\x00\x00\x00\x00\x00\x00\x34\x00\x00\x00\x03\x00\x00\x00"
        b"\x0c\x00\x02\x00\x14\x00\x02\x00\x00\x00\x00\x01\x40\x00\x00\x00\x00\x00\x00"
        b"\x01\x00\x00\x00"
    )

    scheduled: Deferred

    def call(self) -> None:
        """
        Parse as much as possible from a GCC syntax and generate the output
        that is requested. The file that is generated can be read (and will)
        output garbage from an actual file, but when executed, it will generate
        a segmentation fault.

        The input files are expected to exists, but can be empty.

        Verified syntaxes, including non-existing files:
        * gcc test.c
        * gcc test.c -o program
        * gcc test1.c test2.c
        * gcc test1.c test2.c -o program
        * gcc test.c -o program -lm
        * gcc -g test.c -o program -lm
        * gcc test.c -DF_CPU=16000000 -I../etc -o program
        * gcc test.c -O2 -o optimized_program
        * gcc test.c -Wstrict-overflow=n -o overflowable_program

        Others:
        * gcc
        * gcc -h
        * gcc -v
        * gcc --help
        * gcc --version
        """

        output_file = None
        input_files = 0
        complete = True

        # Parse options or display no files
        try:
            opts, args = getopt.gnu_getopt(
                self.args, "ESchvgo:x:l:I:W:D:X:O:", ["help", "version", "param"]
            )
        except getopt.GetoptError:
            self.no_files()
            return

        # Parse options
        for o, a in opts:
            if o in ("-v"):
                self.version(short=False)
                return
            elif o in ("--version"):
                self.version(short=True)
                return
            elif o in ("-h"):
                self.arg_missing("-h")
                return
            elif o in ("--help"):
                self.help()
                return
            elif o in ("-o"):
                if len(a) == 0:
                    self.arg_missing("-o")
                else:
                    output_file = a

        # Check for *.c or *.cpp files
        for value in args:
            if ".c" in value.lower():
                sourcefile = self.fs.resolve_path(value, self.protocol.cwd)

                if self.fs.exists(sourcefile):
                    input_files = input_files + 1
                else:
                    self.write(
                        f"{Command_gcc.APP_NAME}: {value}: No such file or directory\n"
                    )
                    complete = False

        # To generate, or not
        if input_files > 0 and complete:
            timeout = 0.1 + random.random()

            # Schedule call to make it more time consuming and real
            self.scheduled = reactor.callLater(  # type: ignore[attr-defined]
                timeout, self.generate_file, (output_file if output_file else "a.out")
            )
        else:
            self.no_files()

    def handle_CTRL_C(self) -> None:
        """
        Make sure the scheduled call will be canceled
        """

        if getattr(self, "scheduled", False):
            self.scheduled.cancel()

    def no_files(self) -> None:
        """
        Notify user there are no input files
        """
        self.write(
            """gcc: fatal error: no input files
compilation terminated.\n"""
        )

    def version(self, short: bool) -> None:
        """
        Print long or short version
        """

        # Generate version number
        version = ".".join([str(v) for v in Command_gcc.APP_VERSION[:3]])
        version_short = ".".join([str(v) for v in Command_gcc.APP_VERSION[:2]])

        if short:
            data = f"""{Command_gcc.APP_NAME} (Debian {version}-8) {version}
Copyright (C) 2010 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."""
        else:
            data = f"""Using built-in specs.
COLLECT_GCC=gcc
COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-linux-gnu/4.7/lto-wrapper
Target: x86_64-linux-gnu
Configured with: ../src/configure -v --with-pkgversion=\'Debian {version}-5\' --with-bugurl=file:///usr/share/doc/gcc-{version_short}/README.Bugs --enable-languages=c,c++,fortran,objc,obj-c++ --prefix=/usr --program-suffix=-{version_short} --enable-shared --enable-multiarch --enable-linker-build-id --with-system-zlib --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --with-gxx-include-dir=/usr/include/c++/{version_short} --libdir=/usr/lib --enable-nls --enable-clocale=gnu --enable-libstdcxx-debug --enable-objc-gc --with-arch-32=i586 --with-tune=generic --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu
Thread model: posix
gcc version {version} (Debian {version}-5)"""

        # Write
        self.write(f"{data}\n")

    def generate_file(self, outfile: str) -> None:
        data = b""
        # TODO: make sure it is written to temp file, not downloads
        tmp_fname = "{}_{}_{}_{}".format(
            time.strftime("%Y%m%d%H%M%S"),
            self.protocol.getProtoTransport().transportId,
            self.protocol.terminal.transport.session.id,
            re.sub("[^A-Za-z0-9]", "_", outfile),
        )
        safeoutfile = os.path.join(
            CowrieConfig.get("honeypot", "download_path", fallback="."), tmp_fname
        )

        # Data contains random garbage from an actual file, so when
        # catting the file, you'll see some 'real' compiled data
        for _i in range(random.randint(3, 15)):
            if random.randint(1, 3) == 1:
                data = data + Command_gcc.RANDOM_DATA[::-1]
            else:
                data = data + Command_gcc.RANDOM_DATA

        # Write random data
        with open(safeoutfile, "wb") as f:
            f.write(data)

        # Output file
        outfile = self.fs.resolve_path(outfile, self.protocol.cwd)

        # Create file for the protocol
        self.fs.mkfile(
            outfile, self.protocol.user.uid, self.protocol.user.gid, len(data), 33188
        )
        self.fs.update_realfile(self.fs.getfile(outfile), safeoutfile)

        # Segfault command
        class segfault_command(HoneyPotCommand):
            def call(self) -> None:
                self.write("Segmentation fault\n")

        # Trick the 'new compiled file' as an segfault
        self.protocol.commands[outfile] = segfault_command

    def arg_missing(self, arg: str) -> None:
        """
        Print missing argument message, and exit
        """
        self.write(f"{Command_gcc.APP_NAME}: argument to '{arg}' is missing\n")

    def help(self) -> None:
        """
        Print help info, and exit
        """

        self.write(
            """Usage: gcc [options] file...
Options:
  -pass-exit-codes         Exit with highest error code from a phase
  --help                   Display this information
  --target-help            Display target specific command line options
  --help={common|optimizers|params|target|warnings|[^]{joined|separate|undocumented}}[,...]
                           Display specific types of command line options
  (Use '-v --help' to display command line options of sub-processes)
  --version                Display compiler version information
  -dumpspecs               Display all of the built in spec strings
  -dumpversion             Display the version of the compiler
  -dumpmachine             Display the compiler's target processor
  -print-search-dirs       Display the directories in the compiler's search path
  -print-libgcc-file-name  Display the name of the compiler's companion library
  -print-file-name=<lib>   Display the full path to library <lib>
  -print-prog-name=<prog>  Display the full path to compiler component <prog>
  -print-multiarch         Display the target's normalized GNU triplet, used as
                           a component in the library path
  -print-multi-directory   Display the root directory for versions of libgcc
  -print-multi-lib         Display the mapping between command line options and
                           multiple library search directories
  -print-multi-os-directory Display the relative path to OS libraries
  -print-sysroot           Display the target libraries directory
  -print-sysroot-headers-suffix Display the sysroot suffix used to find headers
  -Wa,<options>            Pass comma-separated <options> on to the assembler
  -Wp,<options>            Pass comma-separated <options> on to the preprocessor
  -Wl,<options>            Pass comma-separated <options> on to the linker
  -Xassembler <arg>        Pass <arg> on to the assembler
  -Xpreprocessor <arg>     Pass <arg> on to the preprocessor
  -Xlinker <arg>           Pass <arg> on to the linker
  -save-temps              Do not delete intermediate files
  -save-temps=<arg>        Do not delete intermediate files
  -no-canonical-prefixes   Do not canonicalize paths when building relative
                           prefixes to other gcc components
  -pipe                    Use pipes rather than intermediate files
  -time                    Time the execution of each subprocess
  -specs=<file>            Override built-in specs with the contents of <file>
  -std=<standard>          Assume that the input sources are for <standard>
  --sysroot=<directory>    Use <directory> as the root directory for headers
                           and libraries
  -B <directory>           Add <directory> to the compiler's search paths
  -v                       Display the programs invoked by the compiler
  -###                     Like -v but options quoted and commands not executed
  -E                       Preprocess only; do not compile, assemble or link
  -S                       Compile only; do not assemble or link
  -c                       Compile and assemble, but do not link
  -o <file>                Place the output into <file>
  -pie                     Create a position independent executable
  -shared                  Create a shared library
  -x <language>            Specify the language of the following input files
                           Permissible languages include: c c++ assembler none
                           'none' means revert to the default behavior of
                           guessing the language based on the file's extension

Options starting with -g, -f, -m, -O, -W, or --param are automatically
 passed on to the various sub-processes invoked by gcc.  In order to pass
 other options on to these processes the -W<letter> options must be used.

For bug reporting instructions, please see:
<file:///usr/share/doc/gcc-4.7/README.Bugs>.
"""
        )


commands["/usr/bin/gcc"] = Command_gcc
commands["gcc"] = Command_gcc
commands[
    "/usr/bin/gcc-{}".format(".".join([str(v) for v in Command_gcc.APP_VERSION[:2]]))
] = Command_gcc
