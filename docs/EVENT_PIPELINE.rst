.. SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

Event Pipeline Design
#####################

This document describes how Cowrie events travel from the code that observes
attacker activity to the output plugins, the defects in that pipeline, and the
design that replaces it: a session-scoped event log feeding a single central
dispatcher. The event *schema* (the event ids and their attributes) is
documented in :doc:`OUTPUT` and is unchanged by this design.

Terminology
***********

event
    A dictionary describing one observed action, carrying an ``eventid``
    (e.g. ``cowrie.session.file_download``), a human-readable ``message`` or
    ``format``, and event-specific attributes.

session
    The unique identifier of one attacker connection
    (``transportId``, e.g. ``ce8abc71b984``). This is the key output
    consumers correlate on.

sessionno
    A transport counter with an ``S`` (SSH) or ``T`` (Telnet) prefix, e.g.
    ``T1475``. An internal artifact of the current pipeline; not part of the
    event schema.

output plugin
    A subclass of ``cowrie.core.output.Output`` (jsonlog, mysql, s3, ...)
    that receives finished events through its ``write()`` method.

Current architecture
********************

Two parallel paths deliver events to output plugins::

    log.msg(eventid=..., ...)                protocol.logDispatch(eventid=...)
      |                                        |
      v                                        v  adds sessionno
    Twisted global log                       factory.logDispatch()
      |                                        |  prefixes "S"/"T"
      |  every log line, including            |
      |  non-Cowrie Twisted noise             |
      v                                        v
    plugin 1 emit()  plugin 2 emit() ...     for each plugin: logDispatch()
      |                |                       |
      +----------------+-----------------------+
      |
      v
    per-plugin attribution and enrichment, then write()

Every output plugin's ``emit()`` is registered as a *global* Twisted log
observer (``cowrie_plugin.py``), so every log line in the process passes
through every plugin. ``emit()`` filters (no ``eventid`` |rarr| drop) and then
attributes the event to a session using, in order:

1. an explicit ``sessionno`` key (the ``logDispatch`` path);
2. an explicit ``session`` key, reverse-mapped to a sessionno by linear
   search;
3. a regular expression over Twisted's ``system`` log-context string
   (``".*TelnetTransport,([0-9]+),..."``), i.e. the log prefix of whatever
   context the emitting code happened to run in.

The sessionno is then resolved to the session id through a private
``sessions`` dict (and ``src_ip`` through a private ``ips`` dict) that every
plugin instance maintains independently: entries are added when the plugin
sees ``cowrie.session.connect`` and deleted when it sees
``cowrie.session.closed``.

A census of the emitters (July 2026): roughly 108 call sites pass an
``eventid``. About a third carry explicit session identity (the
``logDispatch`` path and the ``session.connect`` events); the other two
thirds are plain ``log.msg`` calls that depend on mechanism 3, the log
context regex.

Defects
*******

1. Events from deferred callbacks are silently lost
===================================================

Mechanism 3 only works when the emitting code runs inside the transport's log
context. Any ``log.msg(eventid=...)`` fired from a deferred callback -- an
HTTP download completing, a DNS lookup, a timer -- carries that callback's
context instead (``system="HTTP11ClientProtocol,client"``), matches neither
regex, and is dropped without trace.

This is not theoretical. When a downloaded script's execution is resumed by a
download callback, the *entire remainder of the script* runs inside the HTTP
client's log context: every ``cowrie.command.input`` event for those commands
is invisible to every database and reporting plugin. The commands an attacker
runs immediately after fetching a payload are precisely the ones a honeypot
exists to record.

2. The session table is deleted while work is still in flight
=============================================================

``cowrie.session.closed`` hard-deletes the plugin's ``sessions``/``ips``
entries, but a download deferred routinely outlives its session: an attacker
disconnects immediately after queueing ``wget``, and the transfer finishes or
fails seconds later. The late ``file_download`` /
``file_download.failed`` event then arrives with a sessionno that no longer
resolves. Until July 2026 this raised ``KeyError`` inside every plugin's
dispatch (an unhandled error in the deferred); it is now dropped instead.
Either way the record of a completed payload download is lost, even though
the emitting code knew the session id perfectly well -- only the table forgot
it.

3. Dual emission as a workaround
================================

Because path 1 does not work from download callbacks, wget and curl emit
every download event *twice*: once via ``logDispatch`` (for the plugins) and
once via ``log.msg`` (for the console log). The two payloads have already
drifted apart in small ways, and the pattern is inconsistent across the
download commands: wget's error path dispatches only, curl's does both, and
tftp/ftpget log their failure line without any ``eventid`` at all. Plugins
receive exactly one copy today only because the ``log.msg`` twin always fails
the context regex -- the deduplication is accidental.

4. N copies of state, N times the work
======================================

Each of the N configured plugins maintains an identical session table and
independently re-runs regex matching, bytes conversion, timestamp formatting,
and message interpolation for *every log line in the process*, including all
non-Cowrie Twisted output. A single plugin that raises from ``write()`` skips
its own ``closed`` cleanup and leaks table entries forever, silently
desynchronizing from its siblings. There is also no error isolation on the
``logDispatch`` path: one plugin raising aborts the dispatch loop for the
plugins after it.

5. Assorted fragility
=====================

The regexes are coupled to Twisted class names (``CowrieTelnetTransport``
happens to match ``.*TelnetTransport``); the ``S``/``T`` prefixing is
duplicated in both factories and re-parsed character-wise in ``emit()``; the
``session`` |rarr| ``sessionno`` reverse lookup is a linear scan; events
arriving before ``connect`` are dropped.

Design goals
************

* Every event is attributed to its session *at the point of emission*, where
  the identity is simply known -- never reconstructed downstream.
* Late events (callbacks that outlive their session) keep full attribution
  and are delivered, not dropped.
* Attribution, enrichment, and lifecycle live in exactly one place.
* One emission call produces both the console log line and the plugin event.
* A plugin failure affects only that plugin.

Non-goals:

* No changes to the event schema in :doc:`OUTPUT`; plugins keep receiving the
  same dictionaries through the same ``write()`` method.
* No changes to the human-readable ``cowrie.log`` format.
* Operational/diagnostic logging (``log.msg`` without an ``eventid``) is out
  of scope and remains plain Twisted logging.

Proposed design
***************

Two new pieces in ``cowrie.core``:

``EventLog`` -- session-scoped emitter
======================================

A small object created by the transport in ``connectionMade()``, carrying the
session's identity once::

    class EventLog:
        """Emits events for one session, with identity bound at creation."""

        def __init__(self, dispatcher, *, session, protocol, src_ip, src_port,
                     dst_ip, dst_port):
            ...

        def dispatch(self, eventid: str, format: str, **fields) -> None:
            """Build the event dict, stamp identity and time, hand it to the
            dispatcher, and emit the formatted console log line."""

The transport owns it (``self.events = EventLog(...)``); the protocol and
commands reach it through the objects they already hold
(``self.protocol.events``). A download command's deferred callbacks close
over the command instance, so a transfer that completes after
``connectionLost`` still holds the ``EventLog`` and its event arrives fully
attributed -- fixing defect 2 by construction rather than by table lifecycle.
Events dispatched after the session emitted ``cowrie.session.closed`` carry
an additional ``late: true`` attribute so consumers can distinguish them.

``EventDispatcher`` -- single fan-out
=====================================

One instance, owned by the application container (the ``tac``), holding the
plugin list that ``cowrie_plugin.py`` already builds::

    class EventDispatcher:
        def dispatch(self, event: dict) -> None:
            """Enrich once (sensor, timestamp, message interpolation, bytes
            conversion), then deliver to each plugin's write(), isolating
            failures per plugin."""

Enrichment runs once per event instead of once per plugin per log line.
Plugin exceptions are caught, logged, and do not affect other plugins or the
emitting session. The per-plugin ``sessions``/``ips`` tables, the regexes,
and the global log observer registration are deleted at the end of the
migration; ``Output`` shrinks to ``start()``/``stop()``/``write()``.

Events without a session
========================

A few emitters are not tied to an attacker session (backend pool state,
proxy backend bookkeeping). These call ``dispatcher.dispatch()`` directly
with whatever identity they have. The current pipeline drops most of them
anyway (they match no regex); making them first-class is deliberately left
until the main migration is done.

Event flow after the change
===========================

::

    command / protocol / transport
      |
      |  self.protocol.events.dispatch(eventid=..., ...)
      v
    EventLog (identity bound at connectionMade)
      |                       \
      v                        v
    EventDispatcher          console log line (once)
      |  enrich once
      v
    plugin.write()  x N, error-isolated

Migration plan
**************

The old and new pipelines can run side by side; an event travels exactly one
of them, so nothing is double-delivered.

Phase 1 -- introduce
    Add ``EventLog`` and ``EventDispatcher``; transports create the
    ``EventLog`` and keep emitting the old way. No behavior change.

Phase 2 -- convert the bleeding edges
    Convert the download commands (wget, curl, tftp, ftpget, scp) and the
    other ``logDispatch`` call sites. This removes the dual-emission pattern
    and ends the loss of late download events -- the two defects with active
    production impact. The ``factory.logDispatch`` chain becomes unused and
    is removed.

Phase 3 -- sweep
    Convert the remaining ``log.msg(eventid=...)`` sites file by file
    (~45 files, mechanical). Each conversion moves that emitter from
    context-regex attribution to bound identity.

Phase 4 -- delete
    Remove the ``log.addObserver(plugin.emit)`` registration, the regexes,
    the per-plugin tables, and the attribution half of ``Output.emit()``.
    Third-party plugins that only implement ``start``/``stop``/``write``
    are unaffected throughout.

Open questions
**************

* Should ``late`` events be delivered indefinitely, or bounded (e.g. only
  while the command's deferred is pending)? Unbounded matches "never lose a
  download record"; a bound protects consumers that assume session recency.
* Ordering: plugins currently see events in global log order. The dispatcher
  preserves per-session ordering trivially; is cross-session ordering worth
  guaranteeing? (No known consumer depends on it.)
* Whether ``sessionno`` should be dropped from the delivered event once
  nothing derives from it, or kept for operators who grep by transport
  number.

.. |rarr| unicode:: 0x2192
