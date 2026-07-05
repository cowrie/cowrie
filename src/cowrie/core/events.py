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
from os import environ
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
        # The Z suffix (Zulu) only when running in UTC; a local-time
        # timestamp carries its numeric offset instead.
        self.timeFormat: str
        if environ.get("TZ") == "UTC":
            self.timeFormat = "%Y-%m-%dT%H:%M:%S.%fZ"
        else:
            self.timeFormat = "%Y-%m-%dT%H:%M:%S.%f%z"
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
                # Each sink owns its copy, nested containers included:
                # several output plugins mutate the event they receive,
                # which must not corrupt what the sinks after them see.
                # convert() rebuilds dicts and lists recursively, so it
                # doubles as the per-sink deep copy.
                sink.write(convert(ev))
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

    # Attribution keys the bound identity always wins over emitter fields:
    # attacker-influenced values (a direct-tcpip request's claimed
    # originator) must not masquerade as the connection's source.
    AUTHORITATIVE = ("session", "src_ip", "protocol")

    def dispatch(self, eventid: str, fmt: str, **fields: Any) -> None:
        event: dict[str, Any] = dict(self.identity)
        event.update(fields)
        for key in self.AUTHORITATIVE:
            if key in self.identity:
                event[key] = self.identity[key]
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
        """The connection ended: events dispatched from now on are late.

        This closes the whole connection's emitter, including on a child:
        only the owning transport calls it. A channel closing is not a
        session end and needs no call here.
        """
        self._root._closed = True


def transport_events(
    factory: Any,
    transport: Any,
    *,
    session: str,
    protocol: str,
    src_ip: str | None = None,
) -> EventLog | None:
    """The session EventLog for a listening transport, bound to the
    connection's endpoints, or None when the running application provides
    no dispatcher. src_ip defaults to the connection peer; the SSH
    transport passes its IPv4-normalized form instead."""
    dispatcher = getattr(getattr(factory, "tac", None), "dispatcher", None)
    if dispatcher is None:
        return None
    peer = transport.getPeer()
    host = transport.getHost()
    return EventLog(
        dispatcher,
        session=session,
        protocol=protocol,
        src_ip=src_ip if src_ip is not None else peer.host,
        src_port=peer.port,
        dst_ip=host.host,
        dst_port=host.port,
    )


class ConsoleRenderer:
    """
    Renders each event's message into the diagnostic log, prefixed with the
    session's identity so the line is attributable no matter which execution
    context emitted the event.
    """

    def __init__(self, logmsg: Callable[..., None] = log.msg) -> None:
        self.logmsg = logmsg

    def write(self, event: dict[str, Any]) -> None:
        message = event.get("message", "")
        if not message:
            # Some events (cowrie.session.params) carry data only; a blank
            # line per session is just log noise.
            return
        system = "{},{},{}".format(
            event.get("protocol", "-"),
            event.get("session", "-"),
            event.get("src_ip", "-"),
        )
        self.logmsg(message, system=system)
