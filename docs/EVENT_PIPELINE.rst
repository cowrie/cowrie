.. SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
..
.. SPDX-License-Identifier: BSD-3-Clause

Event Pipeline Design
#####################

This document describes how Cowrie events travel from the code that observes
attacker activity to the output plugins: a session-scoped event log feeding a
single central dispatcher. The event *schema* (the event ids and their
attributes) is documented in :doc:`OUTPUT`.

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

channel
    One terminal, exec, subsystem, or forwarding stream within a
    connection. SSH multiplexes: a single transport can carry several
    channels, concurrently or in sequence. Telnet has exactly one channel
    per connection.

output plugin
    A subclass of ``cowrie.core.output.Output`` (jsonlog, mysql, s3, ...)
    that receives finished events through its ``write()`` method.

Two streams
***********

Cowrie produces two fundamentally different kinds of output:

diagnostic logging
    Everything Cowrie has to say about itself: debug statements, development
    traces, protocol negotiation detail, factories starting and stopping,
    tracebacks, plugin trouble. Its audience is the developer and the
    operator; its semantics are log semantics (levels, verbosity,
    best-effort, human-formatted). This stream is by nature the larger one:
    most of what it carries never becomes an event. It stays on Twisted's
    logging API and reaches ``cowrie.log``.

events
    The curated subset: structured records of attacker behavior (logins,
    commands, downloads) whose audience is downstream consumers --
    databases, SIEMs, jsonlog. Their semantics are data semantics:
    guaranteed attribution, stable schema, reliable delivery to every
    configured sink. These travel the event pipeline described here.

The two streams are separate all the way down. An event is dispatched exactly
once, to the output plugins and to a built-in console sink that renders its
human-readable line into ``cowrie.log``; the event path has no dependency on
the logging system. ``cowrie.log`` remains the superset it always was: all
diagnostics, plus one rendered line per event, merged chronologically.

Architecture
************

Two pieces in ``cowrie.core.events`` carry every event from emission to the
sinks::

    command / protocol / transport                 diagnostics
      |                                              |
      |  self.protocol.events.dispatch(...)          |  log.msg(...)
      v                                              v
    EventLog (identity bound at connectionMade)    Twisted log --> cowrie.log
      |                                              ^
      v                                              |
    EventDispatcher -- enrich once                   |
      |                                              |
      +--> plugin.write()  x N, error-isolated       |
      +--> console renderer -- one line per event ---+

``EventLog`` -- session-scoped emitter
======================================

A small object created by the transport in ``connectionMade()``, carrying the
session's identity once::

    class EventLog:
        """Emits events for one attacker connection, identity bound at
        creation."""

        def __init__(self, dispatcher, **identity):
            ...

        def dispatch(self, eventid: str, fmt: str, **fields) -> None:
            """Stamp the bound identity, hand the event to the dispatcher."""

The transport owns it (``self.events = EventLog(...)``); the protocol and
commands reach it through the objects they already hold
(``self.protocol.events``), and ``connectionLost`` leaves the reference in
place. Because identity is bound at creation, an event is attributable from
*any* execution context. A download command's deferred callbacks close over
the command instance, so a transfer that completes after ``connectionLost``
still holds the ``EventLog`` and its event arrives fully attributed -- there
is no downstream table that could have forgotten the session.

The bound identity is authoritative: ``session``, ``src_ip``, and
``protocol`` from the identity always win over same-named ``fields`` passed
to ``dispatch()``. This matters because some events carry
attacker-influenced values under those names -- a direct-tcpip request's
claimed originator, for instance -- which must not masquerade as the
connection's real source.

Transports construct the ``EventLog`` and emit the connection event through
one helper::

    self.events = transport_events(
        self.factory, self.transport,
        session=self.transportId, protocol="ssh", src_ip=src_ip,
    )

``transport_events()`` returns the emitter (or ``None`` when the running
application provides no dispatcher, e.g. in some tests) and dispatches
``cowrie.session.connect`` from the bound identity. Symmetrically,
``EventLog.session_closed(duration_ms)`` dispatches ``cowrie.session.closed``
and marks the emitter closed. Keeping both in the ``EventLog`` means the four
transports (ssh, telnet, and the two proxy frontends) do not each carry a
copy of the connection event's id and format string.

Late events
===========

Events dispatched after the connection has closed carry an additional
``late: true`` attribute so consumers can distinguish them. ``late`` refers
to the *connection* having closed, not a channel: a channel ending mid-session
is not late.

Late events exist only while some live object (a pending deferred's command
instance) still references the session's ``EventLog``; when the last
reference is collected, no further events can be emitted for that session.
The bound is therefore the lifetime of in-flight work, not wall time -- an
attacker cannot keep a closed session emitting indefinitely without also
keeping a transfer open, which existing timeouts already bound (treq
``timeout=10``, TFTP retry caps).

Channels
========

``EventLog.child(**extra)`` returns a lightweight view sharing the dispatcher
and the bound connection identity, overlaying extra fields -- the same idea
as a structlog ``bind()`` -- and following the parent connection's closed
state. It is the mechanism by which a channel could add a ``channel``
attribute to every event it dispatches, distinguishing concurrent SSH
channels in the event stream the way the per-channel ttylog and stdin
artifacts already do. The channels do not currently derive a child emitter;
they share the transport's root ``EventLog``. The capability is in place for
when per-channel attribution is wired.

``EventDispatcher`` -- single fan-out
=====================================

One instance, owned by the application container (the ``tac``), holding the
list of sinks -- the configured output plugins plus the console renderer::

    class EventDispatcher:
        def dispatch(self, event: dict) -> None:
            """Enrich once (sensor, uuid, timestamp, message interpolation,
            bytes conversion), then deliver to each sink, isolating failures
            per sink."""

Enrichment runs once per event. Each sink receives its own copy so a plugin
that mutates the event it is handed cannot corrupt what the sinks after it
see. Sink exceptions are caught and logged (rate-limited per sink), and do
not affect other sinks or the emitting session. The dispatcher keeps
counters -- events dispatched, events dropped after stop, per-sink failures
-- as the natural hook for pipeline observability.

Session-less events
===================

Most events carry a ``session``; the output plugins' ``write()`` assumes it.
A few events are operational rather than session-scoped (abuseipdb rate-limit
notices, the plugin-started banner). The dispatcher routes an event with no
``session`` only to sinks that opt in by setting ``accepts_sessionless =
True`` -- the console renderer does. A session-scoped sink never sees a
session-less event and so never has to guard for the missing key.

Output plugins as event sources
===============================

Output plugins are not only sinks. virustotal, reversedns, and greynoise
emit session-attributed enrichment events (``cowrie.virustotal.scanfile``,
``cowrie.reversedns.connect``, ...) and abuseipdb emits session-less
operational events. These are events, not diagnostics, and must reach every
configured sink. Plugins therefore hold a reference to the ``EventDispatcher``
(set on the ``Output`` base class before any plugin loads, so an event
dispatched from a plugin's ``start()`` is delivered) and emit through
``Output.dispatch()``, carrying the attribution of the event that triggered
them, into the same fan-out as everything else.

The console renderer -- events back into ``cowrie.log``
=======================================================

Developers and operators read one merged, chronological ``cowrie.log`` in
which event lines sit among the (far more numerous) diagnostic lines. A small
built-in sink renders each event's ``message`` into that log, stamping the
session's ``protocol,session,src_ip`` prefix explicitly. Rendered from the
attributed event, a line carries its session no matter where the emitting
code ran -- a download callback's lines no longer appear under
``[HTTP11ClientProtocol,client]``, making concurrent sessions distinguishable
in the log. Rendering is thereby just another consumer -- jsonlog renders to
JSON, the console renderer renders to the diagnostic log -- rather than
something the emitter does as a side effect.

Calling patterns
****************

A shell emitter such as command input, attributed by the bound identity and
delivered from any execution context::

    self.protocol.events.dispatch("cowrie.command.input", "CMD: %(input)s",
                                  input=line)

A download command's completion callback. If this fires after the attacker
disconnected, the event arrives with ``late: true`` and full attribution, and
the console renderer prints it under the session's log prefix::

    def collectioncomplete(self, data: None) -> None:
        ...
        self.protocol.events.dispatch(
            "cowrie.session.file_download",
            "Downloaded URL (%(url)s) with SHA-256 %(shasum)s to %(outfile)s",
            url=self.url.decode(),
            outfile=self.artifact.shasumFilename,
            shasum=self.artifact.shasum,
            duplicate=self.artifact.duplicate,
        )

A transport-level event, e.g. the SSH client version string::

    self.events.dispatch(
        "cowrie.client.version",
        "Remote SSH version: %(version)s",
        version=self.otherVersionString,
    )

An output plugin emitting an enrichment event for the event it is
processing::

    self.dispatch(
        eventid="cowrie.virustotal.scanfile",
        format="VT: New file %(sha256)s",
        session=event["session"],
        src_ip=event["src_ip"],
        protocol=event["protocol"],
        sha256=event["shasum"],
    )

Login events attach the session's emitter to the credential object rather
than reaching a transport directly, since the credential is what the auth
checker receives::

    creds = UsernamePasswordIP(username, password, src_ip, events=self.events)

For public-key authentication Twisted constructs the credential internally,
so the SSH userauth service wraps the portal for that one call
(``EventsAttachingPortal``) and attaches the transport's emitter to whatever
credential passes through, letting the public-key checker dispatch attributed
events.

Operational considerations
**************************

No configuration changes
    Plugin selection, loading, and configuration are untouched;
    ``cowrie_plugin.py`` builds the same plugin list and hands it to the
    dispatcher. An upgrade is a restart.

Plugin failure handling
    ``write()`` exceptions are caught per plugin and rate-limited (first
    failure, then periodic summaries), so an unreachable database does not
    turn every attacker keystroke into an error line and flood ``cowrie.log``.
    One plugin raising does not stop delivery to the others.

Shutdown
    The dispatcher and each plugin's ``stop()`` run at *after*-shutdown, so
    the final events of connections torn down during shutdown
    (``cowrie.session.closed``, the ttylog-closed record) deliver before a
    sink's backend (a database pool, an hpfeeds client) is closed. The
    dispatcher tolerates dispatch-after-stop (drop and count) so a late
    deferred firing during teardown cannot raise into the reactor.

Blocking plugins
    ``write()`` is called synchronously in the reactor thread -- a plugin
    doing blocking I/O stalls the honeypot. The dispatcher is the single
    place a delivery queue or thread pool could be added later.

Pipeline observability
    The dispatcher's counters (events dispatched, dropped, per-sink failures)
    are the natural point to expose delivery health -- turning "is my ELK
    feed complete?" from guesswork into a metric. They are maintained but not
    yet surfaced to a plugin or command.

Log volume
    ``cowrie.log`` content is unchanged: one console line per event, plus
    diagnostics as before. Plugins no longer scan every Twisted log line, so
    per-event plugin work is (events x N plugins), not (all log lines x N
    plugins).

Security considerations
***********************

Audit-trail integrity
    Per-plugin error isolation means a plugin crash -- including one
    triggered by crafted attacker input -- cannot suppress delivery of that
    event to the remaining plugins. There is no per-plugin session table left
    to desynchronize.

Attacker-controlled data
    Event fields (commands, URLs, filenames, version strings) are attacker
    input, and the bound identity overrides same-named fields so an attacker
    cannot spoof ``session``/``src_ip``/``protocol`` in the structured
    output. The dispatcher's enrichment step is the single choke point where
    console rendering could additionally strip control characters and escape
    sequences (log-injection via ``\n`` or ANSI codes) while the structured
    event keeps the raw bytes for forensics; that stripping is a candidate
    for future work.

Event floods
    An attacker spamming commands generates events at line rate, unchanged
    from before. The dispatcher's counters provide a detection hook;
    rate-limiting event *generation* stays with the emitting subsystems
    (e.g. the download rate limiter).

Testing
*******

``EventLog`` and ``EventDispatcher`` are plain objects with no dependency on
the global Twisted log, so unit tests inject a capturing fake sink and assert
on delivered dictionaries -- no log-observer fixtures, no regex setup. The
helpers in ``cowrie.test.eventcapture`` (``capture_eventlog``,
``capture_events``, ``events_of``, ``make_exec_transport``) wire a capturing
pipeline onto a protocol or transport; the shell tests' ``FakeTransport``
carries one so command tests can assert on ``tr.dispatchedEvents``.

Diagnostics on ``twisted.logger``
*********************************

The diagnostic side runs on per-class ``twisted.logger.Logger`` instances:
each emitting class carries ``_log = Logger()`` (modules with free functions
carry one at module level), giving every line a namespace derived from its
origin (``cowrie.ssh.transport.HoneyPotSSHTransport``,
``cowrie.commands.wget``) and a real level. The legacy
``twisted.python.log`` API is no longer used for diagnostics.

Levels and namespaces
    ``python/logfile.py`` wraps the log observer -- ``cowrie.log``, or
    stdout in foreground and Docker mode -- in a ``FilteringLogObserver``
    driven by configuration: ``[honeypot] log_level`` sets the default
    (info), and ``log_level_<namespace>`` options (or the equivalent
    ``COWRIE_HONEYPOT_LOG_LEVEL_*`` environment variables) override per
    subsystem by dotted prefix -- debug a single subsystem in production
    without drowning in the rest (``log_level_cowrie.ssh = debug``).
    Overrides work at module granularity: configparser lowercases option
    names, so a class-qualified namespace cannot be targeted, but the
    module prefix above it covers it. Filtering happens at the observer,
    so test observers and any future sinks still see everything.

Session prefixes
    ``twisted.logger`` does not read the reactor's ``ILogContext``, which
    is where legacy ``log.msg`` lines inherited their
    ``[HoneyPotSSHTransport,3,1.2.3.4]`` prefix. The observer in
    ``python/logfile.py`` restores it: a diagnostic emitted inside a
    connection's context is stamped with that system prefix (keeping it
    correlatable to a session in the log), while lines outside any
    connection context render their ``namespace#level``. Level filtering
    uses the namespace either way.

Lazy formatting
    Diagnostic messages are PEP-3101 format strings with the runtime values
    passed as keywords: ``self._log.debug("block {n} received", n=num)``
    costs nearly nothing when filtered out, so debug statements can stay in
    the code permanently. Runtime values are never interpolated into the
    format string itself -- attacker-controlled text (commands, URLs,
    version strings) may contain braces and must stay data, the same rule
    the event pipeline applies to its authoritative fields.

Failures
    ``self._log.failure("wget transfer failed")`` replaces ``log.err``,
    capturing the active exception with its traceback as structured data.

Console event lines
    The console renderer emits through a ``Logger`` under the
    ``cowrie.events`` namespace, stamping the session's
    ``protocol,session,src_ip`` prefix via ``log_system``. That namespace
    keeps an explicit ``info`` floor: raising the global ``log_level``
    quiets diagnostics without silently erasing the attack record from
    the log, preserving ``cowrie.log`` as the superset. Operators who do
    want event lines filtered set ``log_level_cowrie.events`` explicitly.

The backend pool's session-less emitters historically carried
``eventid=`` markers on the legacy API without ever reaching the output
plugins; they are deliberately plain diagnostics, converted like the
rest -- pool bookkeeping is about the honeypot's own infrastructure,
not attacker behavior, so it does not become events. The SSH connection
service keeps the last legacy import in product code, for
``log.callWithLogger``, which is not a diagnostic emitter.

Why not ``twisted.logger`` for events too
=========================================

Twisted's own answer to structured events is the ``twisted.logger`` package:
``Logger`` objects emitting keyword-structured events into observer chains.
It is the right modernization for Cowrie's *diagnostic* logging (above), but
not for the event pipeline: ``twisted.logger`` has no bound context that
survives a deferred hop, so events fired from a download callback would lose
their attribution -- exactly the failure the ``EventLog`` exists to prevent.
A ``ContextVar`` holding the current session's emitter was also considered
and rejected: every reactor entry point would have to set it, and one missed
entry point misattributes events silently. In a security event stream, a loud
``AttributeError`` on a missing ``self.events`` is preferable to quietly
wrong data.

The chosen design -- an explicit emitter object delivered through a single
publisher -- is not how Twisted routes its own logs, and that is deliberate:
security events are domain data with delivery guarantees, not diagnostics. It
does follow Twisted's shape where it matters: ``EventDispatcher`` is
structurally a domain-specific ``LogPublisher``, including the per-observer
error isolation Twisted's publisher has.
