# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from __future__ import annotations

import getopt
import hashlib
import os
import re
import time

from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_scp(HoneyPotCommand):
    """
    scp command
    """

    download_path = CowrieConfig.get("honeypot", "download_path")
    download_path_uniq = CowrieConfig.get(
        "honeypot", "download_path_uniq", fallback=download_path
    )

    out_dir: str = ""

    def help(self) -> None:
        self.write(
            """usage: scp [-12346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]
           [-l limit] [-o ssh_option] [-P port] [-S program]
           [[user@]host1:]file1 ... [[user@]host2:]file2\n"""
        )

    def start(self) -> None:
        try:
            optlist, args = getopt.getopt(self.args, "12346BCpqrvfstdv:cFiloPS:")
        except getopt.GetoptError:
            self.help()
            self.exit()
            return

        self.out_dir = ""

        for opt in optlist:
            if opt[0] == "-d":
                self.out_dir = args[0]
                break

        if self.out_dir:
            outdir = self.fs.resolve_path(self.out_dir, self.protocol.cwd)

            if not self.fs.exists(outdir):
                self.errorWrite(f"-scp: {self.out_dir}: No such file or directory\n")
                self.exit()

        self.write("\x00")
        self.write("\x00")
        self.write("\x00")
        self.write("\x00")
        self.write("\x00")
        self.write("\x00")
        self.write("\x00")
        self.write("\x00")
        self.write("\x00")
        self.write("\x00")

    def lineReceived(self, line: str) -> None:
        log.msg(
            eventid="cowrie.session.file_download",
            realm="scp",
            input=line,
            format="INPUT (%(realm)s): %(input)s",
        )
        self.protocol.terminal.write("\x00")

    def drop_tmp_file(self, data: bytes, name: str) -> None:
        tmp_fname = "{}-{}-{}-scp_{}".format(
            time.strftime("%Y%m%d-%H%M%S"),
            self.protocol.getProtoTransport().transportId,
            self.protocol.terminal.transport.session.id,
            re.sub("[^A-Za-z0-9]", "_", name),
        )

        self.safeoutfile = os.path.join(self.download_path, tmp_fname)

        with open(self.safeoutfile, "wb+") as f:
            f.write(data)

    def save_file(self, data: bytes, fname: str) -> None:
        self.drop_tmp_file(data, fname)

        if os.path.exists(self.safeoutfile):
            with open(self.safeoutfile, "rb"):
                shasum = hashlib.sha256(data).hexdigest()
                hash_path = os.path.join(self.download_path_uniq, shasum)

            # If we have content already, delete temp file
            if not os.path.exists(hash_path):
                os.rename(self.safeoutfile, hash_path)
                duplicate = False
            else:
                os.remove(self.safeoutfile)
                duplicate = True

            log.msg(
                format='SCP Uploaded file "%(filename)s" to %(outfile)s',
                eventid="cowrie.session.file_upload",
                filename=os.path.basename(fname),
                duplicate=duplicate,
                url=fname,
                outfile=shasum,
                shasum=shasum,
                destfile=fname,
            )

            # Update the honeyfs to point to downloaded file
            self.fs.update_realfile(self.fs.getfile(fname), hash_path)
            self.fs.chown(fname, self.protocol.user.uid, self.protocol.user.gid)

    def parse_scp_data(self, data: bytes) -> bytes:
        # scp data format:
        # C0XXX filesize filename\nfile_data\x00
        # 0XXX - file permissions
        # filesize - size of file in bytes in decimal notation

        pos = data.find(b"\n")
        if pos != -1:
            header = data[:pos]

            pos += 1

            if re.match(rb"^C0[\d]{3} [\d]+ [^\s]+$", header):
                r = re.search(rb"C(0[\d]{3}) ([\d]+) ([^\s]+)", header)

                if r and r.group(1) and r.group(2) and r.group(3):
                    dend = pos + int(r.group(2))

                    if dend > len(data):
                        dend = len(data)

                    d = data[pos:dend]

                    if self.out_dir:
                        fname = os.path.join(self.out_dir, r.group(3).decode())
                    else:
                        fname = r.group(3).decode()

                    outfile = self.fs.resolve_path(fname, self.protocol.cwd)

                    try:
                        self.fs.mkfile(outfile, 0, 0, r.group(2), r.group(1))
                    except fs.FileNotFound:
                        # The outfile locates at a non-existing directory.
                        self.errorWrite(f"-scp: {outfile}: No such file or directory\n")
                        return b""

                    self.save_file(d, outfile)

                    data = data[dend + 1 :]  # cut saved data + \x00
            else:
                data = b""
        else:
            data = b""

        return data

    def handle_CTRL_D(self) -> None:
        if (
            self.protocol.terminal.stdinlogOpen
            and self.protocol.terminal.stdinlogFile
            and os.path.exists(self.protocol.terminal.stdinlogFile)
        ):
            with open(self.protocol.terminal.stdinlogFile, "rb") as f:
                data: bytes = f.read()
                header: bytes = data[: data.find(b"\n")]
                if re.match(rb"C0[\d]{3} [\d]+ [^\s]+", header):
                    content = data[data.find(b"\n") + 1 :]
                else:
                    content = b""

            if content:
                with open(self.protocol.terminal.stdinlogFile, "wb") as f:
                    f.write(content)

        self.exit()


commands["/usr/bin/scp"] = Command_scp
commands["scp"] = Command_scp
