# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Test helper that wires a capturing event pipeline onto a protocol.
# ABOUTME: Lets command tests assert on dispatched events instead of log calls.

from __future__ import annotations

from typing import Any

from cowrie.core.events import EventDispatcher, EventLog


class CaptureSink:
    """An event sink that records every event it receives."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(event)


def capture_events(protocol: Any, **identity: Any) -> list[dict[str, Any]]:
    """Install a capturing EventLog on ``protocol`` and return the list its
    events land in. The console renderer is omitted so nothing reaches the
    Twisted log during tests."""
    sink = CaptureSink()
    dispatcher = EventDispatcher([sink], logmsg=lambda *a, **kw: None)
    base = {"session": "test0000", "protocol": "test", "src_ip": "203.0.113.1"}
    base.update(identity)
    protocol.events = EventLog(dispatcher, **base)
    return sink.events
