# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the cap on shell input size ([shell] max_input_size).
# ABOUTME: Oversized script files and command lines are refused before parsing.

from __future__ import annotations

import os
import tempfile
import unittest
from typing import ClassVar

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "

# The default [shell] max_input_size; tests build inputs just past it.
LIMIT = 16384


class InputSizeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()


class OversizedScriptFileTests(InputSizeTestCase):
    """sh/bash refuse a script file larger than max_input_size instead of
    feeding it to the parser, whose cost grows superlinearly with input size:
    a downloaded HTML error page run with `sh x` (a dead payload URL) could
    otherwise block the reactor for hours."""

    def setUp(self) -> None:
        super().setUp()
        self._tempfiles: list[str] = []

    def tearDown(self) -> None:
        super().tearDown()
        for path in self._tempfiles:
            os.unlink(path)

    def plant_file(self, path: str, contents: bytes) -> None:
        """Create a honeyfs file backed by a real file, bypassing the shell:
        a redirect could not write it, as the command line itself would
        exceed the input cap."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(contents)
            self._tempfiles.append(f.name)
        self.proto.fs.mkfile(path, 0, 0, len(contents), 0o644)
        self.proto.fs.update_realfile(self.proto.fs.getfile(path), f.name)

    def test_sh_refuses_oversized_script(self) -> None:
        self.plant_file("/tmp/big.sh", b"echo OVERSIZED\n" * 1100)
        self.proto.lineReceived(b"sh /tmp/big.sh")
        output = self.tr.value()
        self.assertIn(b"cannot execute binary file", output)
        self.assertNotIn(b"OVERSIZED", output)
        self.assertTrue(output.endswith(PROMPT))

    def test_bash_refuses_oversized_script(self) -> None:
        self.plant_file("/tmp/big2.sh", b"echo OVERSIZED\n" * 1100)
        self.proto.lineReceived(b"bash /tmp/big2.sh")
        output = self.tr.value()
        self.assertIn(b"cannot execute binary file", output)
        self.assertNotIn(b"OVERSIZED", output)

    def test_dotslash_refuses_oversized_script(self) -> None:
        self.plant_file("/tmp/big3.sh", b"#!/bin/sh\n" + b"echo OVERSIZED\n" * 1100)
        self.proto.lineReceived(b"/tmp/big3.sh")
        output = self.tr.value()
        self.assertIn(b"cannot execute binary file", output)
        self.assertNotIn(b"OVERSIZED", output)

    def test_script_at_limit_still_runs(self) -> None:
        # Exactly at the cap is allowed; only strictly larger is refused.
        filler = b"# " + b"x" * (LIMIT - len(b"# \necho SMALL\n")) + b"\n"
        contents = filler + b"echo SMALL\n"
        self.assertEqual(len(contents), LIMIT)
        self.plant_file("/tmp/small.sh", contents)
        self.proto.lineReceived(b"sh /tmp/small.sh")
        output = self.tr.value()
        self.assertIn(b"SMALL", output)
        self.assertNotIn(b"cannot execute binary file", output)


class OversizedLineTests(InputSizeTestCase):
    """The shell refuses to parse a single input line larger than
    max_input_size, reporting it like a syntax error; this also covers
    piped input and `sh -c`, which reuse lineReceived."""

    def test_long_line_refused(self) -> None:
        self.proto.lineReceived(b"echo SHOULD_NOT_RUN; : " + b"A" * (LIMIT + 1))
        output = self.tr.value()
        self.assertNotIn(b"SHOULD_NOT_RUN", output)
        self.assertIn(b"syntax error", output)
        self.assertTrue(output.endswith(PROMPT))

    def test_long_line_sets_exit_status(self) -> None:
        self.proto.lineReceived(b": " + b"A" * (LIMIT + 1))
        self.tr.clear()
        self.proto.lineReceived(b"echo rc=$?")
        self.assertEqual(self.tr.value(), b"rc=2\n" + PROMPT)

    def test_shell_survives_long_line(self) -> None:
        self.proto.lineReceived(b": " + b"A" * (LIMIT + 1))
        self.tr.clear()
        self.proto.lineReceived(b"echo still_alive")
        self.assertEqual(self.tr.value(), b"still_alive\n" + PROMPT)

    def test_line_at_limit_still_parses(self) -> None:
        line = b"echo ATLIMIT #" + b"x" * (LIMIT - len(b"echo ATLIMIT #"))
        self.assertEqual(len(line), LIMIT)
        self.proto.lineReceived(line)
        output = self.tr.value()
        self.assertIn(b"ATLIMIT", output)
        self.assertNotIn(b"syntax error", output)


class _HoldTerminal(HoneyPotCommand):
    """A command that holds the terminal like a download in progress; typed
    lines are queued on the shell until finish() releases it."""

    pending: ClassVar[list[_HoldTerminal]] = []

    def start(self) -> None:
        _HoldTerminal.pending.append(self)

    def finish(self) -> None:
        self.exit()


class OversizedQueuedLineTests(InputSizeTestCase):
    """A line typed while a command holds the terminal goes through
    queue_line, which parses at queue time and needs the same cap."""

    def setUp(self) -> None:
        super().setUp()
        _HoldTerminal.pending = []
        self.proto.commands["holdterm"] = _HoldTerminal

    def tearDown(self) -> None:
        del self.proto.commands["holdterm"]
        super().tearDown()

    def test_queued_long_line_refused(self) -> None:
        self.proto.lineReceived(b"holdterm")
        self.proto.lineReceived(b"echo SHOULD_NOT_RUN; : " + b"A" * (LIMIT + 1))
        _HoldTerminal.pending[0].finish()
        output = self.tr.value()
        self.assertNotIn(b"SHOULD_NOT_RUN", output)
        self.assertIn(b"syntax error", output)
        self.assertTrue(output.endswith(PROMPT))


if __name__ == "__main__":
    unittest.main()
