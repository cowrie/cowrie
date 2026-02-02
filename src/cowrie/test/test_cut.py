# Copyright (c) 2026 Michel Oosterhof
# See LICENSE for details.
from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellCutCommandTests(unittest.TestCase):
    """Test for cowrie/commands/cut.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_cut_single_field_tab_delimiter(self) -> None:
        """cut -f1 on tab-delimited input selects the first field."""
        self.proto.lineReceived(b"echo 'one\ttwo\tthree' | cut -f1\n")
        self.assertEqual(self.tr.value(), b"one\n" + PROMPT)

    def test_cut_second_field_tab_delimiter(self) -> None:
        """cut -f2 on tab-delimited input selects the second field."""
        self.proto.lineReceived(b"echo 'one\ttwo\tthree' | cut -f2\n")
        self.assertEqual(self.tr.value(), b"two\n" + PROMPT)

    def test_cut_custom_delimiter(self) -> None:
        """cut -d: -f2 uses colon as delimiter."""
        self.proto.lineReceived(b"echo 'a:b:c' | cut -d: -f2\n")
        self.assertEqual(self.tr.value(), b"b\n" + PROMPT)

    def test_cut_multiple_fields(self) -> None:
        """cut -d, -f1,3 selects fields 1 and 3."""
        self.proto.lineReceived(b"echo 'a,b,c,d' | cut -d, -f1,3\n")
        self.assertEqual(self.tr.value(), b"a,c\n" + PROMPT)

    def test_cut_field_range(self) -> None:
        """cut -d, -f2-4 selects fields 2 through 4."""
        self.proto.lineReceived(b"echo 'a,b,c,d,e' | cut -d, -f2-4\n")
        self.assertEqual(self.tr.value(), b"b,c,d\n" + PROMPT)

    def test_cut_open_end_range(self) -> None:
        """cut -d, -f3- selects field 3 to end."""
        self.proto.lineReceived(b"echo 'a,b,c,d,e' | cut -d, -f3-\n")
        self.assertEqual(self.tr.value(), b"c,d,e\n" + PROMPT)

    def test_cut_open_start_range(self) -> None:
        """cut -d, -f-2 selects fields 1 through 2."""
        self.proto.lineReceived(b"echo 'a,b,c,d' | cut -d, -f-2\n")
        self.assertEqual(self.tr.value(), b"a,b\n" + PROMPT)

    def test_cut_multiline_input(self) -> None:
        """cut processes each line independently."""
        self.proto.lineReceived(b"printf 'a:b:c\nd:e:f\n' | cut -d: -f2\n")
        self.assertEqual(self.tr.value(), b"b\ne\n" + PROMPT)

    def test_cut_no_delimiter_in_line(self) -> None:
        """Lines without the delimiter are printed unchanged (default behavior)."""
        self.proto.lineReceived(b"echo 'nodels' | cut -d: -f2\n")
        self.assertEqual(self.tr.value(), b"nodels\n" + PROMPT)

    def test_cut_no_delimiter_with_s_flag(self) -> None:
        """With -s, lines without the delimiter are suppressed."""
        self.proto.lineReceived(b"echo 'nodels' | cut -d: -f2 -s\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_cut_field_out_of_range(self) -> None:
        """Requesting a field beyond available fields outputs empty."""
        self.proto.lineReceived(b"echo 'a,b' | cut -d, -f5\n")
        self.assertEqual(self.tr.value(), b"\n" + PROMPT)

    def test_cut_missing_field_spec(self) -> None:
        """cut without -f or -b or -c should produce an error."""
        self.proto.lineReceived(b"echo 'test' | cut -d,\n")
        self.assertIn(
            b"cut: you must specify a list of bytes, characters, or fields",
            self.tr.value(),
        )

    def test_cut_help(self) -> None:
        """cut --help shows usage information."""
        self.proto.lineReceived(b"cut --help\n")
        self.assertIn(b"Usage: cut", self.tr.value())

    def test_cut_no_input(self) -> None:
        """cut with no input and no file waits for stdin then exits on CTRL-D."""
        self.proto.lineReceived(b"cut -d, -f1\n")
        self.proto.handle_CTRL_D()
        self.assertEqual(self.tr.value(), PROMPT)
