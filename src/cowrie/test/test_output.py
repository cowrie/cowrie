# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/core/output.py, the output plugin base class.
# ABOUTME: Verifies emit() session attribution, including late events after close.

from __future__ import annotations

import unittest
from typing import Any

from cowrie.core.output import Output


class CapturingOutput(Output):
    """Output plugin that records what write() receives."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        super().__init__()

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class EmitSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.output = CapturingOutput()

    def connect(self, sessionno: str = "T99", session: str = "abcd0123") -> None:
        self.output.emit(
            {
                "eventid": "cowrie.session.connect",
                "sessionno": sessionno,
                "session": session,
                "src_ip": "192.0.2.1",
                "message": "connect",
            }
        )

    def test_event_gets_session_attribution(self) -> None:
        self.connect()
        self.output.emit(
            {
                "eventid": "cowrie.command.input",
                "sessionno": "T99",
                "message": "CMD",
            }
        )
        self.assertEqual(len(self.output.events), 2)
        self.assertEqual(self.output.events[1]["session"], "abcd0123")
        self.assertEqual(self.output.events[1]["src_ip"], "192.0.2.1")

    def test_late_event_after_close_is_dropped(self) -> None:
        # A download callback can fire after the session closed (the deferred
        # outlives connectionLost). Its event can no longer be attributed to a
        # session and must be dropped, not raise KeyError.
        self.connect()
        self.output.emit(
            {
                "eventid": "cowrie.session.closed",
                "sessionno": "T99",
                "message": "closed",
            }
        )
        written = len(self.output.events)
        self.output.emit(
            {
                "eventid": "cowrie.session.file_download.failed",
                "sessionno": "T99",
                "message": "late download failure",
            }
        )
        self.assertEqual(
            len(self.output.events),
            written,
            "late event for a closed session must be dropped, not written",
        )
