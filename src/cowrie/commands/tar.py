# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import os
import tarfile

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_REALFILE

commands = {}


class Command_tar(HoneyPotCommand):
    def mkfullpath(self, path: str, f: tarfile.TarInfo) -> None:
        components, d = path.split("/"), []
        while len(components):
            d.append(components.pop(0))
            p = "/".join(d)
            if p and not self.fs.exists(p):
                self.fs.mkdir(p, 0, 0, 4096, f.mode, f.mtime)

    def call(self) -> None:
        if len(self.args) < 2:
            self.write("tar: You must specify one of the `-Acdtrux' options\n")
            self.write("Try `tar --help' or `tar --usage' for more information.\n")
            return

        filename = self.args[1]

        extract = False
        if "x" in self.args[0]:
            extract = True
        verbose = False
        if "v" in self.args[0]:
            verbose = True

        path = self.fs.resolve_path(filename, self.protocol.cwd)
        if not path or not self.protocol.fs.exists(path):
            self.write(f"tar: {filename}: Cannot open: No such file or directory\n")
            self.write("tar: Error is not recoverable: exiting now\n")
            self.write("tar: Child returned status 2\n")
            self.write("tar: Error exit delayed from previous errors\n")
            return

        hpf = self.fs.getfile(path)
        if not hpf[A_REALFILE]:
            self.write("tar: this does not look like a tar archive\n")
            self.write("tar: skipping to next header\n")
            self.write("tar: error exit delayed from previous errors\n")
            return

        try:
            t = tarfile.open(hpf[A_REALFILE])
        except Exception:
            self.write("tar: this does not look like a tar archive\n")
            self.write("tar: skipping to next header\n")
            self.write("tar: error exit delayed from previous errors\n")
            return

        for f in t:
            dest = self.fs.resolve_path(f.name.strip("/"), self.protocol.cwd)
            if verbose:
                self.write(f"{f.name}\n")
            if not extract or not len(dest):
                continue
            if f.isdir():
                self.fs.mkdir(dest, 0, 0, 4096, f.mode, f.mtime)
            elif f.isfile():
                self.mkfullpath(os.path.dirname(dest), f)
                self.fs.mkfile(dest, 0, 0, f.size, f.mode, f.mtime)
            else:
                log.msg(f"tar: skipping [{f.name}]")


commands["/bin/tar"] = Command_tar
commands["tar"] = Command_tar
