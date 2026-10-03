# SPDX-FileCopyrightText: 2020 Peter Šufliarsky
# SPDX-FileCopyrightText: 2020 Peter Sufliarsky
# SPDX-FileCopyrightText: 2020-2024 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import os
import stat
import tempfile
import unittest

from cowrie.shell import fs
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

TRY_CHMOD_HELP_MSG = b"Try 'chmod --help' for more information.\n"
PROMPT = b"root@unitTest:~# "


class ShellChmodCommandTests(unittest.TestCase):
    """Test for cowrie/commands/chmod.py."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()

    def test_chmod_command_001(self) -> None:
        self.proto.lineReceived(b"chmod")
        self.assertEqual(
            self.tr.value(), b"chmod: missing operand\n" + TRY_CHMOD_HELP_MSG + PROMPT
        )

    def test_chmod_command_002(self) -> None:
        self.proto.lineReceived(b"chmod -x")
        self.assertEqual(
            self.tr.value(), b"chmod: missing operand\n" + TRY_CHMOD_HELP_MSG + PROMPT
        )

    def test_chmod_command_003(self) -> None:
        self.proto.lineReceived(b"chmod +x")
        self.assertEqual(
            self.tr.value(),
            b"chmod: missing operand after \xe2\x80\x98+x\xe2\x80\x99\n"
            + TRY_CHMOD_HELP_MSG
            + PROMPT,
        )

    def test_chmod_command_004(self) -> None:
        self.proto.lineReceived(b"chmod -A")
        self.assertEqual(
            self.tr.value(),
            b"chmod: invalid option -- 'A'\n" + TRY_CHMOD_HELP_MSG + PROMPT,
        )

    def test_chmod_command_005(self) -> None:
        self.proto.lineReceived(b"chmod --A")
        self.assertEqual(
            self.tr.value(),
            b"chmod: unrecognized option '--A'\n" + TRY_CHMOD_HELP_MSG + PROMPT,
        )

    def test_chmod_command_006(self) -> None:
        self.proto.lineReceived(b"chmod -x abcd")
        self.assertEqual(
            self.tr.value(),
            b"chmod: cannot access 'abcd': No such file or directory\n" + PROMPT,
        )

    def test_chmod_command_007(self) -> None:
        self.proto.lineReceived(b"chmod abcd efgh")
        self.assertEqual(
            self.tr.value(),
            b"chmod: invalid mode: \xe2\x80\x98abcd\xe2\x80\x99\n"
            + TRY_CHMOD_HELP_MSG
            + PROMPT,
        )

    def test_chmod_command_008(self) -> None:
        # Valid symbolic and numeric modes on an existing file succeed
        # silently, whatever the mode spelling or target path form.
        for command in (
            b"chmod +x .bashrc",
            b"chmod -R +x .bashrc",
            b"chmod +x /root/.bashrc",
            b"chmod +x ~/.bashrc",
            b"chmod a+x .bashrc",
            b"chmod ug+x .bashrc",
            b"chmod 777 .bashrc",
            b"chmod 0755 .bashrc",
        ):
            with self.subTest(command=command):
                self.proto.lineReceived(command)
                self.assertEqual(self.tr.value(), PROMPT)
                self.tr.clear()


class ShellChmodModeTests(unittest.TestCase):
    """chmod changes the permission bits of its targets the way GNU chmod does."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)
        cls.proto.lineReceived(b"mkdir /tmp/modes")
        cls.proto.lineReceived(b"cd /tmp/modes")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()

    def run_line(self, line: bytes) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line)
        output: bytes = self.tr.value()
        return output.removesuffix(b"root@unitTest:/tmp/modes# ")

    def mode_of(self, path: str) -> int:
        node = self.proto.fs.getfile(path)
        assert node is not None
        mode: int = node[fs.A_MODE]
        return mode

    def make_file(self, name: str, perm: int) -> str:
        path = f"/tmp/modes/{name}"
        self.run_line(f"echo hi > {name}".encode())
        self.proto.fs.chmod(path, perm)
        return path

    def test_symbolic_modes(self) -> None:
        for n, (spec, before, after) in enumerate(
            (
                ("+x", 0o644, 0o755),
                ("u+x", 0o644, 0o744),
                ("go-r", 0o644, 0o600),
                ("a=r", 0o644, 0o444),
                ("u+x,go-r", 0o644, 0o700),
                ("u=g", 0o640, 0o440),
                ("go=u", 0o700, 0o777),
                ("u=", 0o644, 0o044),
                ("u+s", 0o755, 0o4755),
                ("g+s", 0o755, 0o2755),
                ("o+s", 0o755, 0o755),
                ("+t", 0o755, 0o1755),
                ("u+t", 0o755, 0o755),
                ("a+X", 0o644, 0o644),
                ("a+X", 0o744, 0o755),
                ("u-x+w", 0o544, 0o644),
            )
        ):
            with self.subTest(spec=spec, before=oct(before)):
                path = self.make_file(f"sym{n}", before)
                self.assertEqual(self.run_line(f"chmod {spec} sym{n}".encode()), b"")
                self.assertEqual(stat.S_IMODE(self.mode_of(path)), after)
                self.assertTrue(stat.S_ISREG(self.mode_of(path)))

    def test_octal_operator_modes(self) -> None:
        for n, (spec, before, after) in enumerate(
            (
                ("-7", 0o777, 0o770),
                ("+111", 0o644, 0o755),
                ("=600", 0o777, 0o600),
                ("0755", 0o600, 0o755),
                ("4755", 0o600, 0o4755),
            )
        ):
            with self.subTest(spec=spec):
                path = self.make_file(f"oct{n}", before)
                self.assertEqual(self.run_line(f"chmod {spec} oct{n}".encode()), b"")
                self.assertEqual(stat.S_IMODE(self.mode_of(path)), after)

    def test_umask_limits_modes_without_who(self) -> None:
        # With no u/g/o/a, the umask (022) bits are left alone, and GNU chmod
        # reports the difference from what a+... would have given.
        for n, (spec, before, after, message) in enumerate(
            (
                ("+w", 0o444, 0o644, b"rw-r--r--, not rw-rw-rw-"),
                ("-w", 0o666, 0o466, b"r--rw-rw-, not r--r--r--"),
                ("=r", 0o666, 0o466, b"r--rw-rw-, not r--r--r--"),
            )
        ):
            with self.subTest(spec=spec):
                path = self.make_file(f"um{n}", before)
                self.assertEqual(
                    self.run_line(f"chmod {spec} um{n}; echo $?".encode()),
                    f"chmod: um{n}: new permissions are ".encode() + message + b"\n1\n",
                )
                self.assertEqual(stat.S_IMODE(self.mode_of(path)), after)

    def test_directory_keeps_type_and_gets_X(self) -> None:
        self.run_line(b"mkdir d")
        self.proto.fs.chmod("/tmp/modes/d", 0o700)
        self.assertEqual(self.run_line(b"chmod a+X d"), b"")
        self.assertEqual(stat.S_IMODE(self.mode_of("/tmp/modes/d")), 0o711)
        self.assertTrue(stat.S_ISDIR(self.mode_of("/tmp/modes/d")))
        self.assertEqual(self.run_line(b"chmod 750 d"), b"")
        self.assertEqual(stat.S_IMODE(self.mode_of("/tmp/modes/d")), 0o750)
        self.assertTrue(stat.S_ISDIR(self.mode_of("/tmp/modes/d")))

    def test_star_changes_every_visible_entry(self) -> None:
        self.run_line(b"mkdir /tmp/modes/star")
        self.run_line(b"cd /tmp/modes/star")
        try:
            for name in ("a", "b", ".hidden"):
                self.run_line(f"echo hi > {name}".encode())
                self.proto.fs.chmod(f"/tmp/modes/star/{name}", 0o644)
            self.tr.clear()
            self.proto.lineReceived(b"chmod 700 *")
            self.assertEqual(self.tr.value(), b"root@unitTest:/tmp/modes/star# ")
            for name, perm in (("a", 0o700), ("b", 0o700), (".hidden", 0o644)):
                self.assertEqual(
                    stat.S_IMODE(self.mode_of(f"/tmp/modes/star/{name}")), perm
                )
        finally:
            self.run_line(b"cd /tmp/modes")

    def test_mode_out_of_range_is_invalid(self) -> None:
        self.make_file("f", 0o644)
        self.assertEqual(
            self.run_line(b"chmod 77777 f"),
            "chmod: invalid mode: ‘77777’\n".encode() + TRY_CHMOD_HELP_MSG,
        )
        self.assertEqual(stat.S_IMODE(self.mode_of("/tmp/modes/f")), 0o644)
