# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Asserts that commands reading attacker stdin dispatch their input
# ABOUTME: events through the session EventLog with bound identity.

from __future__ import annotations

import os
import unittest
from typing import TypeVar

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

T = TypeVar("T", bound=HoneyPotCommand)


class CommandInputEventTests(unittest.TestCase):
    """Each interactive command that consumes stdin must dispatch its input
    event through the session EventLog, so the event carries the session
    identity from any execution context."""

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

    def assert_input_event(
        self, command: bytes, eventid: str, realm: str, line: bytes = b"stdin line"
    ) -> None:
        self.proto.lineReceived(command + b"\n")
        self.proto.lineReceived(line)
        events = [e for e in self.tr.dispatchedEvents if e["eventid"] == eventid]
        self.assertEqual(
            len(events), 1, f"expected one {eventid} event, got {events!r}"
        )
        ev = events[0]
        self.assertEqual(ev["realm"], realm)
        self.assertEqual(ev["input"], line.decode())
        self.assertEqual(ev["session"], "test-suite")
        self.proto.handle_CTRL_C()
        self.tr.clear()

    def make_command(self, cmdclass: type[T], *args: str) -> T:
        """Instantiate a command outside the shell; commands need the
        protocol's process protocol, which exists once any command has run."""
        self.proto.lineReceived(b"echo\n")
        self.tr.clear()
        return cmdclass(self.proto, *args)

    def assert_direct_input_event(
        self, command: HoneyPotCommand, eventid: str, realm: str
    ) -> None:
        """For commands whose start() always exits, so the shell never routes
        stdin to them: dispatch must still work when lineReceived is driven
        directly (e.g. from a pipe)."""
        command.lineReceived("stdin line")
        events = [e for e in self.tr.dispatchedEvents if e["eventid"] == eventid]
        self.assertEqual(
            len(events), 1, f"expected one {eventid} event, got {events!r}"
        )
        self.assertEqual(events[0]["realm"], realm)
        self.assertEqual(events[0]["input"], "stdin line")
        self.assertEqual(events[0]["session"], "test-suite")

    def test_awk_input_event(self) -> None:
        from cowrie.commands.awk import Command_awk

        cmd = self.make_command(Command_awk, "awk", "{ print }")
        cmd.code = []
        self.assert_direct_input_event(cmd, "cowrie.session.input", "awk")

    def test_base64_input_event(self) -> None:
        self.assert_input_event(b"base64", "cowrie.session.input", "base64")

    def test_cat_input_event(self) -> None:
        self.assert_input_event(b"cat", "cowrie.session.input", "cat")

    def test_chpasswd_input_event(self) -> None:
        self.assert_input_event(
            b"chpasswd", "cowrie.command.input", "chpasswd", line=b"root:hunter2"
        )

    def test_chpasswd_password_change_event(self) -> None:
        self.proto.lineReceived(b"chpasswd\n")
        self.proto.lineReceived(b"root:hunter2\n")
        events = [
            e
            for e in self.tr.dispatchedEvents
            if e["eventid"] == "cowrie.command.chpasswd"
        ]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["username"], "root")
        self.assertEqual(events[0]["session"], "test-suite")
        self.proto.handle_CTRL_C()
        self.tr.clear()

    def test_crontab_input_event(self) -> None:
        self.assert_input_event(b"crontab -", "cowrie.command.input", "crontab")

    def test_cut_input_event(self) -> None:
        self.assert_input_event(b"cut -c1", "cowrie.command.input", "cut")

    def test_dd_input_event(self) -> None:
        self.assert_input_event(b"dd", "cowrie.session.input", "dd")

    def test_grep_input_event(self) -> None:
        from cowrie.commands.fs import Command_grep

        cmd = self.make_command(Command_grep, "grep", "stdin")
        self.assert_direct_input_event(cmd, "cowrie.command.input", "grep")

    def test_tail_input_event(self) -> None:
        self.assert_input_event(b"tail", "cowrie.command.input", "tail")

    def test_head_input_event(self) -> None:
        self.assert_input_event(b"head", "cowrie.command.input", "head")

    def test_passwd_input_event(self) -> None:
        self.assert_input_event(b"passwd", "cowrie.command.success", "passwd")

    def test_php_input_event(self) -> None:
        self.assert_input_event(b"php", "cowrie.command.success", "php")

    def test_perl_input_event(self) -> None:
        self.assert_input_event(b"perl", "cowrie.command.input", "perl")

    def test_python_input_event(self) -> None:
        self.assert_input_event(b"python", "cowrie.command.input", "python")

    def test_tee_input_event(self) -> None:
        self.assert_input_event(b"tee", "cowrie.session.input", "tee")

    def test_uniq_input_event(self) -> None:
        self.assert_input_event(b"uniq", "cowrie.command.input", "uniq")

    def test_wc_input_event(self) -> None:
        from cowrie.commands.wc import Command_wc

        cmd = self.make_command(Command_wc, "wc")
        self.assert_direct_input_event(cmd, "cowrie.command.input", "wc")

    def test_busybox_command_found_event(self) -> None:
        self.proto.lineReceived(b"busybox ls\n")
        events = [
            e
            for e in self.tr.dispatchedEvents
            if e["eventid"] == "cowrie.command.success"
        ]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["input"], "ls")
        self.assertEqual(events[0]["session"], "test-suite")
