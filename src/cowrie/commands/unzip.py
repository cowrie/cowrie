# Copyright (c) 2020 Julius ter Pelkwijk <pelkwijk@gmail.com>
# Based on code made by Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import os
import zipfile

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_REALFILE

commands = {}


class Command_unzip(HoneyPotCommand):
    def mkfullpath(self, path: str) -> None:
        components, d = path.split("/"), []
        while len(components):
            d.append(components.pop(0))
            directory = "/" + "/".join(d)
            if not self.fs.exists(directory):
                self.fs.mkdir(
                    directory,
                    self.protocol.user.uid,
                    self.protocol.user.gid,
                    4096,
                    33188,
                )

    def call(self) -> None:
        if len(self.args) == 0 or self.args[0].startswith("-"):
            output = (
                "UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.\n"
                "\n"
                "Usage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]\n"
                "  Default action is to extract files in list, except those in xlist, to exdir;\n"
                '  file[.zip] may be a wildcard.  -Z => ZipInfo mode ("unzip -Z" for usage).\n'
                "\n"
                "  -p  extract files to pipe, no messages     -l  list files (short format)\n"
                "  -f  freshen existing files, create none    -t  test compressed archive data\n"
                "  -u  update files, create if necessary      -z  display archive comment only\n"
                "  -v  list verbosely/show version info       -T  timestamp archive to latest\n"
                "  -x  exclude files that follow (in xlist)   -d  extract files into exdir\n"
                "modifiers:\n"
                "   -n  never overwrite existing files         -q  quiet mode (-qq => quieter)\n"
                "  -o  overwrite files WITHOUT prompting      -a  auto-convert any text files\n"
                "  -j  junk paths (do not make directories)   -aa treat ALL files as text\n"
                "  -U  use escapes for all non-ASCII Unicode  -UU ignore any Unicode fields\n"
                "  -C  match filenames case-insensitively     -L  make (some) names lowercase\n"
                "  -X  restore UID/GID info                   -V  retain VMS version numbers\n"
                '  -K  keep setuid/setgid/tacky permissions   -M  pipe through "more" pager\n'
                'See "unzip -hh" or unzip.txt for more help.  Examples:\n'
                "  unzip data1 -x joe   => extract all files except joe from zipfile data1.zip\n"
                "  unzip -p foo | more  => send contents of foo.zip via pipe into program more\n"
                "  unzip -fo foo ReadMe => quietly replace existing ReadMe if archive file newer\n"
            )
            self.write(output)
            return

        filename = self.args[0]

        path = self.fs.resolve_path(filename, self.protocol.cwd)
        if not path:
            self.write(
                f"unzip:  cannot find or open {filename}, {filename}.zip or {filename}.ZIP.\n"
            )
            return
        if not self.protocol.fs.exists(path):
            if not self.protocol.fs.exists(path + ".zip"):
                self.write(
                    f"unzip:  cannot find or open {filename}, {filename}.zip or {filename}.ZIP.\n"
                )
                return
            else:
                path = path + ".zip"

        f = self.fs.getfile(path)
        if not f[A_REALFILE]:
            output = (
                "  End-of-central-directory signature not found.  Either this file is not\n"
                "  a zipfile, or it constitutes one disk of a multi-part archive.  In the\n"
                "  latter case the central directory and zipfile comment will be found on\n"
                "  the last disk(s) of this archive.\n"
            )
            self.write(output)
            self.write(
                f"unzip:  cannot find or open {filename}, {filename}.zip or {filename}.ZIP.\n"
            )
            return

        try:
            t = zipfile.ZipFile(f[A_REALFILE]).infolist()
        except Exception:
            output = (
                "  End-of-central-directory signature not found.  Either this file is not\n"
                "  a zipfile, or it constitutes one disk of a multi-part archive.  In the\n"
                "  latter case the central directory and zipfile comment will be found on\n"
                "  the last disk(s) of this archive.\n"
            )
            self.write(output)
            self.write(
                f"unzip:  cannot find or open {filename}, {filename}.zip or {filename}.ZIP.\n"
            )
            return
        self.write(f"Archive:  {filename}\n")
        for f in t:
            dest = self.fs.resolve_path(f.filename.strip("/"), self.protocol.cwd)
            self.write(f"  inflating: {f.filename}\n")
            if not len(dest):
                continue
            if f.is_dir():
                self.fs.mkdir(
                    dest, self.protocol.user.uid, self.protocol.user.gid, 4096, 33188
                )
            elif not f.is_dir():
                self.mkfullpath(os.path.dirname(dest))
                self.fs.mkfile(
                    dest,
                    self.protocol.user.uid,
                    self.protocol.user.gid,
                    f.file_size,
                    33188,
                )
            else:
                log.msg(f"  skipping: {f.filename}\n")


commands["/bin/unzip"] = Command_unzip
commands["unzip"] = Command_unzip
