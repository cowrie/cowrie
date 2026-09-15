# SPDX-FileCopyrightText: 2015-2024 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import getopt
import hashlib
import os
import posixpath
import re

from cowrie.core.artifact import temp_download_path
from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_scp(HoneyPotCommand):
    """
    scp command
    """

    download_path = CowrieConfig.get("honeypot", "download_path", fallback=".")
    download_path_uniq = CowrieConfig.get(
        "honeypot", "download_path_uniq", fallback=download_path
    )
    # Every uploaded file costs a real temp-file write, a sha256 hash and a
    # rename on the host filesystem, so cap how many files one upload session
    # can save regardless of how small each file is.
    max_files_per_session: int = CowrieConfig.getint(
        "shell", "scp_max_files_per_session", fallback=20
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
            # -d takes no getopt argument of its own; the target directory is
            # the first positional argument, which need not be there.
            if opt[0] == "-d" and args:
                self.out_dir = args[0]
                break

        if self.out_dir:
            outdir = self.fs.resolve_path(self.out_dir, self.cwd)

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
        self.protocol.events.dispatch(
            "cowrie.session.input",
            "INPUT (%(realm)s): %(input)s",
            realm="scp",
            input=line,
        )
        self.write("\x00")

    def drop_tmp_file(self, data: bytes) -> None:
        self.safeoutfile = temp_download_path("scp")

        with open(self.safeoutfile, "wb+") as f:
            f.write(data)

    def save_file(self, data: bytes, fname: str) -> None:
        self.drop_tmp_file(data)

        if os.path.exists(self.safeoutfile):
            shasum = hashlib.sha256(data).hexdigest()
            hash_path = os.path.join(self.download_path_uniq, shasum)

            # If we have content already, delete temp file
            if not os.path.exists(hash_path):
                os.rename(self.safeoutfile, hash_path)
                duplicate = False
            else:
                os.remove(self.safeoutfile)
                duplicate = True

            self.protocol.events.dispatch(
                "cowrie.session.file_upload",
                'SCP Uploaded file "%(filename)s" to %(outfile)s',
                filename=posixpath.basename(fname),
                duplicate=duplicate,
                url=fname,
                outfile=shasum,
                shasum=shasum,
                destfile=fname,
            )

            # Update the honeyfs to point to downloaded file. The entry is
            # absent when mkfile could not create it (e.g. the filesystem is at
            # its new-file quota), in which case there is nothing to point at.
            f = self.fs.getfile(fname)
            if f:
                self.fs.update_realfile(f, hash_path)
                self.fs.chown(fname, self.user["uid"], self.user["gid"])

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
                    # Both fields are attacker-controlled: the filesize can
                    # exceed int()'s digit limit (~4300, the CVE-2020-10735
                    # mitigation) and the permissions regex admits non-octal
                    # digits. Treat either conversion failing as a malformed
                    # header rather than raising out of eofReceived().
                    try:
                        filesize = int(r.group(2))
                        fileperm = int(r.group(1), 8)
                    except ValueError:
                        return b""

                    dend = pos + filesize

                    if dend > len(data):
                        dend = len(data)

                    d = data[pos:dend]

                    # The filename is attacker-controlled and need not be
                    # valid UTF-8; still capture the upload under a
                    # best-effort name.
                    scpname = r.group(3).decode(errors="replace")

                    if self.out_dir:
                        fname = posixpath.join(self.out_dir, scpname)
                    else:
                        fname = scpname

                    outfile = self.fs.resolve_path(fname, self.cwd)

                    try:
                        self.fs.mkfile(
                            outfile,
                            self.user["uid"],
                            self.user["gid"],
                            filesize,
                            fileperm,
                        )
                    except fs.FileNotFound:
                        # The outfile locates at a non-existing directory.
                        self.errorWrite(f"-scp: {outfile}: No such file or directory\n")
                        return b""
                    except fs.PermissionDenied:
                        # The outfile locates in a protected path (e.g. /proc).
                        self.errorWrite(f"-scp: {outfile}: Permission denied\n")
                        return b""

                    try:
                        self.save_file(d, outfile)
                    except OSError as e:
                        # A real filesystem failure (disk full, missing or
                        # unwritable download_path) while writing the temp
                        # file or renaming it into place. Log it and stop the
                        # upload cleanly instead of raising out of
                        # eofReceived() and leaving the temp file behind.
                        self._log.error(
                            "scp: error saving upload {fname}: {error!r}",
                            fname=fname,
                            error=e,
                        )
                        safeoutfile = getattr(self, "safeoutfile", None)
                        if safeoutfile and os.path.exists(safeoutfile):
                            os.remove(safeoutfile)
                        return b""

                    data = data[dend + 1 :]  # cut saved data + \x00
            else:
                data = b""
        else:
            data = b""

        return data

    def eofReceived(self) -> None:
        terminal = self.protocol.terminal
        if (
            terminal.stdinlogOpen
            and terminal.stdinlogFile
            and os.path.exists(terminal.stdinlogFile)
        ):
            with open(terminal.stdinlogFile, "rb") as f:
                data: bytes = f.read()

            # Decode the SCP wire protocol into the uploaded file(s), each saved
            # as content only. The raw stdin log still holds the framing (header,
            # body and trailing ACK), so remove it to avoid saving it again as a
            # download.
            filecount = 0
            while data:
                if filecount >= self.max_files_per_session:
                    self._log.info(
                        "scp: session reached scp_max_files_per_session "
                        "({max_files}), ignoring the remaining files",
                        max_files=self.max_files_per_session,
                    )
                    break
                data = self.parse_scp_data(data)
                filecount += 1

            terminal.stdinlogOpen = False
            os.remove(terminal.stdinlogFile)

        self.exit()


commands["/usr/bin/scp"] = Command_scp
commands["scp"] = Command_scp
