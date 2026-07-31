# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that shell temp backing files (redirects, gcc, scp) are named
# ABOUTME: prefix + uuid, independent of transport chains and attacker input.

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace

from cowrie.commands.gcc import Command_gcc
from cowrie.commands.scp import Command_scp
from cowrie.core.artifact import temp_download_path
from cowrie.shell import fs
from cowrie.shell.pipe import PipeProtocol

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class _StubFilesystem:
    """Accepts the honeyfs calls the temp-file writers make."""

    def __init__(self) -> None:
        self.realfiles: list[str] = []

    def resolve_path(self, path: str, cwd: str) -> str:
        return path

    def mkfile(self, path: str, uid: int, gid: int, size: int, mode: int) -> bool:
        return True

    def getfile(self, path: str) -> list:
        return []

    def update_realfile(self, f: list, realfile: str) -> None:
        self.realfiles.append(realfile)


class TempFileNamingTests(unittest.TestCase):
    """Temp backing files are named <prefix>_<uuid4 hex>: unique, free of
    attacker-controlled text, and independent of any transport chain
    (issue #40351)."""

    def setUp(self) -> None:
        self.safeoutfiles: list[str] = []

    def tearDown(self) -> None:
        for safeoutfile in self.safeoutfiles:
            if os.path.exists(safeoutfile):
                os.unlink(safeoutfile)

    def assertPrefixUuidName(self, safeoutfile: str, prefix: str) -> None:
        self.safeoutfiles.append(safeoutfile)
        self.assertRegex(os.path.basename(safeoutfile), rf"^{prefix}_[0-9a-f]{{32}}$")
        self.assertTrue(os.path.exists(safeoutfile))

    def _redirect_target(self) -> str:
        protocol = SimpleNamespace(
            user=SimpleNamespace(uid=0, gid=0),
            fs=_StubFilesystem(),
        )
        pipe = PipeProtocol(
            protocol,
            cmd=None,
            cmdargs=[],
            input_data=None,
            next_command=None,
            cwd="/root",
            user={"uid": 0, "gid": 0, "username": "root", "home": "/root"},
        )
        safeoutfile = pipe._create_redirect_target("out.txt")
        assert safeoutfile is not None
        return safeoutfile

    def test_redirect_target(self) -> None:
        self.assertPrefixUuidName(self._redirect_target(), "redir")

    def test_redirect_targets_are_unique(self) -> None:
        first = self._redirect_target()
        second = self._redirect_target()
        self.assertNotEqual(first, second)
        self.assertPrefixUuidName(first, "redir")
        self.assertPrefixUuidName(second, "redir")

    def test_gcc_output_file(self) -> None:
        cmd = Command_gcc.__new__(Command_gcc)
        cmd.fs = _StubFilesystem()
        cmd.cwd = "/root"
        cmd.user = {"uid": 0, "gid": 0, "username": "root", "home": "/root"}
        cmd.protocol = SimpleNamespace(
            user=SimpleNamespace(uid=0, gid=0),
            commands={},
        )
        cmd.generate_file("a.out")
        self.assertEqual(len(cmd.fs.realfiles), 1)
        self.assertPrefixUuidName(cmd.fs.realfiles[0], "gcc")

    def test_scp_dropped_file(self) -> None:
        cmd = Command_scp.__new__(Command_scp)
        cmd.download_path = "/tmp"
        cmd.drop_tmp_file(b"contents")
        self.assertPrefixUuidName(cmd.safeoutfile, "scp")
        with open(cmd.safeoutfile, "rb") as f:
            self.assertEqual(f.read(), b"contents")

    def test_helper_builds_download_dir_paths(self) -> None:
        path = temp_download_path("stdin")
        self.assertEqual(os.path.dirname(path), "/tmp")
        self.assertRegex(os.path.basename(path), r"^stdin_[0-9a-f]{32}$")
        self.assertNotEqual(path, temp_download_path("stdin"))

    def test_sftp_upload_backing_file(self) -> None:
        honeyfs = fs.HoneyPotFilesystem("arch", "/root")
        fd = honeyfs.open("/root/upload.bin", os.O_WRONLY | os.O_CREAT, 33188)
        assert fd is not None
        try:
            self.assertPrefixUuidName(honeyfs.tempfiles[fd], "sftp")
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
