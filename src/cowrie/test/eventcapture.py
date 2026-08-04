# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Test helpers that wire a capturing event pipeline onto protocols,
# ABOUTME: transports, and fake exec channels for asserting dispatched events.

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from cowrie.core.events import EventDispatcher, EventLog


class CaptureSink:
    """An event sink that records every event it receives."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(event)


def _capture_pipeline(sink: CaptureSink, **identity: Any) -> EventLog:
    """An EventLog delivering only to ``sink``, with test identity defaults."""
    bound = {"session": "test0000", "protocol": "test", "src_ip": "1.2.3.4"}
    bound.update(identity)
    return EventLog(
        EventDispatcher([sink], logmsg=lambda *args, **kwargs: None), **bound
    )


def capture_eventlog(**identity: Any) -> tuple[EventLog, list[dict[str, Any]]]:
    """An EventLog whose dispatched events land in the returned list."""
    sink = CaptureSink()
    return _capture_pipeline(sink, **identity), sink.events


def capture_events(protocol: Any, **identity: Any) -> list[dict[str, Any]]:
    """Install a capturing EventLog on ``protocol`` and return the list its
    events land in. The console renderer is omitted so nothing reaches the
    Twisted log during tests."""
    events, dispatched = capture_eventlog(**identity)
    protocol.events = events
    return dispatched


def events_of(events: list[dict[str, Any]], eventid: str) -> list[dict[str, Any]]:
    return [e for e in events if e["eventid"] == eventid]


def make_exec_transport(sink: CaptureSink, processEnded: Any = None) -> SimpleNamespace:
    """The transport.session.conn.transport chain insults expects for an SSH
    exec channel, with an EventLog whose events land in ``sink``."""
    peer = SimpleNamespace(host="1.1.1.1", port=2222)
    inner = SimpleNamespace(sessionno=1, getPeer=lambda: peer)
    factory = SimpleNamespace(starttime=0)
    events = _capture_pipeline(
        sink, session="testexec", protocol="ssh", src_ip="1.1.1.1"
    )
    conn_transport = SimpleNamespace(
        transportId="testexec", factory=factory, transport=inner, events=events
    )
    conn = SimpleNamespace(transport=conn_transport)
    session = SimpleNamespace(id="chan0", conn=conn)
    return SimpleNamespace(
        session=session,
        write=lambda data: None,
        processEnded=processEnded
        if processEnded is not None
        else lambda reason=None: None,
    )
