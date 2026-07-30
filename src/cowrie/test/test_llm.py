# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the LLM backend: attacker input and operator config must
# ABOUTME: not crash a session, and API calls are shared, capped and limited.

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.llm import protocol as llm_protocol


def _avatar() -> MagicMock:
    """An avatar with the attributes the protocols read at construction."""
    avatar = MagicMock()
    avatar.environ = {}
    avatar.server.hostname = "svr04"
    avatar.username = "root"
    return avatar


class ExecCommandDecodeTests(unittest.TestCase):
    def test_non_utf8_exec_command(self) -> None:
        """A non-UTF-8 exec command must leave execcmd usable; every caller
        reads it right after construction."""
        proto = llm_protocol.HoneyPotExecProtocol(_avatar(), b"id\xff")

        self.assertEqual(proto.execcmd, "id�")

    def test_non_utf8_interactive_line(self) -> None:
        """A typed line need not be valid UTF-8."""
        proto = llm_protocol.HoneyPotBaseProtocol(_avatar())
        proto.events = MagicMock()
        sent: list[str] = []
        proto._process_command_with_llm = sent.append  # type: ignore[assignment]

        proto.lineReceived(b"echo \xff")

        self.assertEqual(sent, ["echo �"])


if __name__ == "__main__":
    unittest.main()
