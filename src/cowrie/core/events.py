# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Session-scoped event pipeline: EventLog emitters bound to a session
# ABOUTME: deliver attacker-activity events through one enriching dispatcher.

"""
Events are structured records of attacker behavior, delivered to output
sinks (the configured output plugins and the console renderer) with their
session identity bound at the point of emission. Diagnostic logging is a
separate concern and stays on the Twisted log. See docs/EVENT_PIPELINE.rst
for the design.
"""

from __future__ import annotations

import socket
import time
from typing import TYPE_CHECKING, Any

from twisted.logger import formatTime
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.core.output import convert

if TYPE_CHECKING:
    from collections.abc import Callable

# Log every FAILURE_LOG_INTERVAL'th delivery failure per sink after the
# first, so an unreachable database does not turn every event into an
# error line.
FAILURE_LOG_INTERVAL = 100


class EventDispatcher:
    """
    Delivers events to every sink, enriching each event exactly once and
    isolating sink failures from each other and from the emitting session.
    """

    def __init__(
        self,
        sinks: list[Any],
        logmsg: Callable[..., None] = log.msg,
    ) -> None:
        self.sinks = sinks
        self.logmsg = logmsg
        self.sensor: str = CowrieConfig.get(
            "honeypot", "sensor_name", fallback=socket.gethostname()
        )
        self.uuid: str = CowrieConfig.get("honeypot", "uuid", fallback="unknown")
        self.timeFormat: str = "%Y-%m-%dT%H:%M:%S.%fZ"
        self.stopped: bool = False
        # Delivery bookkeeping, also the hook for pipeline observability.
        self.dispatched: int = 0
        self.dropped_after_stop: int = 0
        self.failures: dict[int, int] = {}  # id(sink) -> failure count

    def dispatch(self, event: dict[str, Any]) -> None:
        if self.stopped:
            self.dropped_after_stop += 1
            return

        ev: dict[str, Any] = convert(event)
        ev["sensor"] = self.sensor
        ev["uuid"] = self.uuid
        if "time" not in ev:
            ev["time"] = time.time()
        ev["timestamp"] = formatTime(ev["time"], timeFormat=self.timeFormat)

        if "format" in ev and "message" not in ev:
            try:
                ev["message"] = ev["format"] % ev
                del ev["format"]
            except (KeyError, TypeError, ValueError):
                ev["message"] = ev["format"]

        self.dispatched += 1
        for sink in self.sinks:
            try:
                sink.write(ev)
            except Exception as e:  # one sink must not stop the rest
                count = self.failures.get(id(sink), 0) + 1
                self.failures[id(sink)] = count
                if count == 1 or count % FAILURE_LOG_INTERVAL == 0:
                    self.logmsg(
                        f"Event sink {sink.__class__.__name__} failed"
                        f" ({count} failures): {e}"
                    )

    def stop(self) -> None:
        """Drop events dispatched during shutdown instead of raising into
        reactor teardown."""
        self.stopped = True


class EventLog:
    """
    Emits events for one attacker connection, with the session identity
    bound at creation so an event is attributable from any execution
    context -- including a deferred callback that outlives the session.
    """

    def __init__(self, dispatcher: EventDispatcher, **identity: Any) -> None:
        self.dispatcher = dispatcher
        self.identity = identity
        self._closed: bool = False
        self._root: EventLog = self

    def dispatch(self, eventid: str, fmt: str, **fields: Any) -> None:
        event: dict[str, Any] = dict(self.identity)
        event.update(fields)
        event["eventid"] = eventid
        event["format"] = fmt
        if self._root._closed:
            event["late"] = True
        self.dispatcher.dispatch(event)

    def child(self, **extra: Any) -> EventLog:
        """A derived emitter (e.g. one SSH channel) that adds ``extra`` to
        every event and follows this connection's closed state."""
        derived = EventLog(self.dispatcher, **{**self.identity, **extra})
        derived._root = self._root
        return derived

    def close(self) -> None:
        """The connection ended: events dispatched from now on are late."""
        self._root._closed = True


class ConsoleRenderer:
    """
    Renders each event's message into the diagnostic log, prefixed with the
    session's identity so the line is attributable no matter which execution
    context emitted the event.
    """

    def __init__(self, logmsg: Callable[..., None] = log.msg) -> None:
        self.logmsg = logmsg

    def write(self, event: dict[str, Any]) -> None:
        system = "{},{},{}".format(
            event.get("protocol", "-"),
            event.get("session", "-"),
            event.get("src_ip", "-"),
        )
        self.logmsg(event.get("message", ""), system=system)
