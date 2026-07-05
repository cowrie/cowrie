# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/core/events.py, the session-scoped event pipeline.
# ABOUTME: Covers dispatcher enrichment/isolation, EventLog identity, and rendering.

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from typing import Any

from cowrie.core.events import ConsoleRenderer, EventDispatcher, EventLog

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class CapturingSink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class SinkFailure(Exception):
    def __init__(self) -> None:
        super().__init__("sink is broken")


class RaisingSink:
    def write(self, event: dict[str, Any]) -> None:
        raise SinkFailure


class EventDispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sink = CapturingSink()
        self.logged: list[str] = []
        self.dispatcher = EventDispatcher(
            [self.sink], logmsg=lambda msg, **kw: self.logged.append(msg)
        )

    def dispatch_one(self, **extra: Any) -> None:
        event: dict[str, Any] = {
            "eventid": "cowrie.command.input",
            "format": "CMD: %(input)s",
            "input": b"ls",
            "session": "abcd0123",
            "protocol": "telnet",
            "src_ip": "192.0.2.1",
        }
        event.update(extra)
        self.dispatcher.dispatch(event)

    def test_enriches_once_and_delivers(self) -> None:
        self.dispatch_one()
        self.assertEqual(len(self.sink.events), 1)
        ev = self.sink.events[0]
        self.assertEqual(ev["message"], "CMD: ls")
        self.assertNotIn("format", ev)
        self.assertEqual(ev["input"], "ls")  # bytes converted
        self.assertIn("sensor", ev)
        self.assertIn("time", ev)
        self.assertIn("timestamp", ev)
        self.assertEqual(ev["session"], "abcd0123")

    def test_sink_failure_is_isolated(self) -> None:
        good = CapturingSink()
        dispatcher = EventDispatcher(
            [RaisingSink(), good], logmsg=lambda msg, **kw: self.logged.append(msg)
        )
        event = {
            "eventid": "cowrie.command.input",
            "format": "CMD",
            "session": "s",
        }
        dispatcher.dispatch(dict(event))
        dispatcher.dispatch(dict(event))
        self.assertEqual(len(good.events), 2, "healthy sink must keep receiving")

    def test_sink_failure_logging_is_rate_limited(self) -> None:
        dispatcher = EventDispatcher(
            [RaisingSink()], logmsg=lambda msg, **kw: self.logged.append(msg)
        )
        for _ in range(10):
            dispatcher.dispatch(
                {"eventid": "cowrie.command.input", "format": "CMD", "session": "s"}
            )
        failure_logs = [m for m in self.logged if "sink is broken" in m]
        self.assertEqual(
            len(failure_logs), 1, "only the first failure is logged verbatim"
        )

    def test_dispatch_after_stop_is_dropped(self) -> None:
        self.dispatcher.stop()
        self.dispatch_one()
        self.assertEqual(self.sink.events, [])


class EventLogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sink = CapturingSink()
        self.dispatcher = EventDispatcher([self.sink], logmsg=lambda msg, **kw: None)
        self.events = EventLog(
            self.dispatcher,
            session="abcd0123",
            protocol="ssh",
            src_ip="192.0.2.1",
            src_port=4711,
            dst_ip="198.51.100.9",
            dst_port=22,
        )

    def test_identity_is_bound(self) -> None:
        self.events.dispatch("cowrie.command.input", "CMD: %(input)s", input="uname -a")
        ev = self.sink.events[0]
        self.assertEqual(ev["eventid"], "cowrie.command.input")
        self.assertEqual(ev["session"], "abcd0123")
        self.assertEqual(ev["protocol"], "ssh")
        self.assertEqual(ev["src_ip"], "192.0.2.1")
        self.assertEqual(ev["message"], "CMD: uname -a")
        self.assertNotIn("late", ev)

    def test_late_after_close(self) -> None:
        self.events.close()
        self.events.dispatch("cowrie.session.file_download", "late download")
        self.assertTrue(self.sink.events[0]["late"])

    def test_child_overlays_and_shares_close(self) -> None:
        channel_events = self.events.child(channel=3)
        channel_events.dispatch("cowrie.command.input", "CMD")
        ev = self.sink.events[0]
        self.assertEqual(ev["channel"], 3)
        self.assertEqual(ev["session"], "abcd0123")
        self.assertNotIn("late", ev)

        self.events.close()
        channel_events.dispatch("cowrie.command.input", "CMD")
        self.assertTrue(
            self.sink.events[1]["late"],
            "a child emitter follows the connection's closed state",
        )


class TelnetTransportEventLogTests(unittest.TestCase):
    """The telnet transport binds an EventLog for the connection's lifetime."""

    def make_transport(self) -> tuple[Any, CapturingSink]:
        from twisted.test.proto_helpers import StringTransport

        from cowrie.telnet.transport import CowrieTelnetTransport

        sink = CapturingSink()
        dispatcher = EventDispatcher([sink], logmsg=lambda msg, **kw: None)
        transport = CowrieTelnetTransport()
        transport.factory = SimpleNamespace(tac=SimpleNamespace(dispatcher=dispatcher))
        tcp = StringTransport()
        tcp.sessionno = 7  # type: ignore[attr-defined]  # the transport logs it
        transport.transport = tcp
        return transport, sink

    def test_eventlog_bound_and_closed_with_connection(self) -> None:
        transport, sink = self.make_transport()
        transport.makeConnection(transport.transport)
        try:
            self.assertIsNotNone(transport.events)
            self.assertEqual(
                transport.events.identity["session"], transport.transportId
            )
            self.assertEqual(transport.events.identity["protocol"], "telnet")

            transport.events.dispatch("cowrie.test", "before close")
            self.assertNotIn("late", sink.events[-1])
        finally:
            transport.connectionLost(None)

        transport.events.dispatch("cowrie.test", "after close")
        self.assertTrue(
            sink.events[-1]["late"],
            "events after connectionLost must be flagged late",
        )


class ConsoleRendererTests(unittest.TestCase):
    def test_renders_with_session_prefix(self) -> None:
        lines: list[tuple[str, str]] = []
        renderer = ConsoleRenderer(
            logmsg=lambda msg, system: lines.append((msg, system))
        )
        renderer.write(
            {
                "eventid": "cowrie.command.input",
                "message": "CMD: ls",
                "session": "abcd0123",
                "protocol": "telnet",
                "src_ip": "192.0.2.1",
            }
        )
        self.assertEqual(lines, [("CMD: ls", "telnet,abcd0123,192.0.2.1")])
