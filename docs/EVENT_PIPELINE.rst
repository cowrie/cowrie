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

channel
    One terminal, exec, subsystem, or forwarding stream within a
    connection. SSH multiplexes: a single transport can carry several
    channels, concurrently or in sequence. Cowrie already captures ttylogs
    and stdin per channel (``insults.py`` keys them by
    ``(transportId, channelId)``), but events carry only the per-transport
    ``session``, so activity on concurrent channels is indistinguishable in
    the event stream. Telnet has exactly one channel per connection.

sessionno
    A transport counter with an ``S`` (SSH) or ``T`` (Telnet) prefix, e.g.
    ``T1475``. An internal artifact of the current pipeline; not part of the
    event schema.

output plugin
    A subclass of ``cowrie.core.output.Output`` (jsonlog, mysql, s3, ...)
    that receives finished events through its ``write()`` method.

Two streams on one channel
**************************

Cowrie produces two fundamentally different kinds of output that today share
one channel, the Twisted log:

diagnostic logging
    Everything Cowrie has to say about itself: debug statements, development
    traces, protocol negotiation detail, factories starting and stopping,
    tracebacks, plugin trouble. Its audience is the developer and the
    operator; its semantics are log semantics (levels, verbosity,
    best-effort, human-formatted). This stream is by nature the larger one:
    most of what it carries never becomes an event.

events
    The curated subset: structured records of attacker behavior (logins,
    commands, downloads) whose audience is downstream consumers --
    databases, SIEMs, jsonlog. Their semantics are data semantics:
    guaranteed attribution, stable schema, reliable delivery to every
    configured sink.

Today the *derivation runs the wrong way*: the curated stream is extracted
from the diagnostic one, by every plugin observing the global log and
regex-parsing context prefixes out of it -- and consequently every debug
line also passes through every plugin's filter. Most of the defects below
are consequences of deriving data from logs. The design inverts the
derivation for attacker activity: the structured event is primary, and its
human-readable line in ``cowrie.log`` is rendered *from* it; purely
diagnostic content -- the bulk of the log -- stays plain Twisted logging
and never touches the event path. ``cowrie.log`` remains the superset it is
today: all diagnostics, plus one rendered line per event, merged
chronologically.

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
* Events and diagnostic logging are separate streams; one emission call per
  event, with the ``cowrie.log`` rendering produced by a sink, not by the
  emitter.
* A plugin failure affects only that plugin.

Non-goals:

* No changes to the event schema in :doc:`OUTPUT`; plugins keep receiving the
  same dictionaries through the same ``write()`` method.
* No changes to the human-readable ``cowrie.log`` format.
* Diagnostic logging keeps its own channel, but converts from the legacy
  ``twisted.python.log`` API to ``twisted.logger`` once the event migration
  frees the log stream from being parsed (see below).

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
(``self.protocol.events``), and ``connectionLost`` leaves the reference in
place. A download command's deferred callbacks close over the command
instance, so a transfer that completes after ``connectionLost`` still holds
the ``EventLog`` and its event arrives fully attributed -- fixing defect 2 by
construction rather than by table lifecycle. Events dispatched after the
session emitted ``cowrie.session.closed`` carry an additional ``late: true``
attribute so consumers can distinguish them.

``dispatch()`` emits the event and nothing else -- it does not write to the
diagnostic log. The familiar event lines in ``cowrie.log`` come from the
console renderer described below, so the event path has no dependency on the
logging system at all.

Channels: one transport, many terminals
=======================================

An SSH transport can carry multiple channels -- several exec or shell
sessions, SFTP, port forwards -- concurrently or in sequence. The transport
owns the root ``EventLog``; a channel derives a child emitter that adds its
identity to every event it dispatches::

    def channelOpened(self):
        self.events = self.conn.transport.events.child(channel=self.id)

``child()`` returns a lightweight view sharing the dispatcher and the bound
connection identity, overlaying extra fields -- the same idea as a
structlog ``bind()``. Commands keep reaching their emitter through
``self.protocol.events`` and need not know whether it is the root or a
child. ``session`` remains the per-connection correlation key, so nothing
changes for existing consumers; ``channel`` is an additive attribute that
finally lets the event stream distinguish what the per-channel ttylog and
stdin artifacts already distinguish, and lets file-transfer events (SCP,
SFTP) name the channel they arrived on. A channel closing does not end the
session: ``late`` refers to the *connection* having closed, not the
channel.

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

The console renderer -- events back into ``cowrie.log``
========================================================

Developers and operators read one merged, chronological ``cowrie.log`` in
which event lines sit among the (far more numerous) diagnostic lines; that
experience is preserved by a small built-in sink that renders each event's
``format`` into a log line and hands it to the diagnostic stream, stamping
the session's ``system`` prefix explicitly. This fixes a long-standing operator pain: a
download callback's lines currently appear under
``[HTTP11ClientProtocol,client]``, making concurrent sessions
indistinguishable in the log; rendered from the attributed event, the line
carries its session no matter where the emitting code ran. Rendering
events is thereby just another consumer -- jsonlog renders to JSON, the
console renderer renders to the diagnostic log -- rather than something the
emitter does as a side effect. Because the renderer only prints dispatcher
events and unconverted emitters still print through their own ``log.msg``,
every event line appears exactly once throughout the migration.

Events without a session
========================

A few emitters are not tied to an attacker session (backend pool state,
proxy backend bookkeeping). These call ``dispatcher.dispatch()`` directly
with whatever identity they have. The current pipeline drops most of them
anyway (they match no regex); making them first-class is deliberately left
until the main migration is done.

Output plugins are not pure sinks: virustotal, reversedns, and greynoise
emit session-attributed enrichment events (``cowrie.virustotal.scanfile``,
``cowrie.reversedns.connect``, ...) and abuseipdb emits session-less
operational events. These are events, not diagnostics: they must reach
every configured sink. Plugins therefore hold a reference to the
``EventDispatcher`` and emit through ``Output.dispatch()``, carrying the
attribution (session, src_ip) of the event that triggered them, into the
same fan-out as everything else.

Calling patterns
================

Transport, at ``connectionMade()`` -- identity is bound exactly once::

    self.events = EventLog(
        self.factory.tac.dispatcher,
        session=self.transportId,
        protocol="telnet",
        src_ip=self.transport.getPeer().host,
        src_port=self.transport.getPeer().port,
        dst_ip=self.transport.getHost().host,
        dst_port=self.transport.getHost().port,
    )
    self.events.dispatch(
        "cowrie.session.connect",
        "New connection: %(src_ip)s:%(src_port)s (%(dst_ip)s:%(dst_port)s)"
        " [session: %(session)s]",
    )

A shell emitter such as command input. Before, in ``shell/honeypot.py``,
attributed by log-context regex and lost when running inside a download
callback::

    log.msg(eventid="cowrie.command.input", input=line, format="CMD: %(input)s")

After -- attributed by the bound identity, delivered from any context::

    self.protocol.events.dispatch("cowrie.command.input", "CMD: %(input)s",
                                  input=line)

A download command's completion callback. Before, in ``commands/wget.py``,
the event is emitted twice (``logDispatch`` for the plugins, ``log.msg`` for
the console) and crashes or is dropped when the transfer outlives the
session. After -- one call, correct in both cases::

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

If this fires after the attacker disconnected, the event arrives with
``late: true`` and full session attribution, and the console renderer prints
it under the session's log prefix rather than the HTTP client's.

A transport-level event, e.g. the SSH client version string::

    self.events.dispatch(
        "cowrie.client.version",
        "Remote SSH version: %(version)s",
        version=self.otherVersionString,
    )

A session-less emitter (backend pool), calling the dispatcher directly::

    self.tac.dispatcher.dispatch(
        {
            "eventid": "cowrie.pool.vm_error",
            "message": f"Backend VM {vm_id} unreachable",
        }
    )

Event flow after the change
===========================

::

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

The diagnostic stream: converting to ``twisted.logger``
*******************************************************

Once no plugin parses the log stream, the diagnostic side gets its own
modernization: from the legacy ``twisted.python.log`` API (~490 ``log.msg``
/ ``log.err`` call sites) to ``twisted.logger``. The observer side is
already there -- ``python/logfile.py`` writes ``cowrie.log`` through
``textFileLogObserver`` and the twistd plugin registers ``ILogObserver``
providers; legacy emissions reach them through Twisted's built-in adapter.
Only the emitters are legacy.

What the conversion buys:

Levels and namespaces
    Per-class ``Logger`` instances give every line a namespace
    (``cowrie.ssh.transport``, ``cowrie.commands.wget``) and a real level.
    Combined with ``LogLevelFilterPredicate`` this yields per-subsystem
    verbosity control from configuration -- debug a single subsystem in
    production without drowning in the rest. Today the log has exactly one
    volume setting: everything.

Lazy formatting
    ``self._log.debug("block {n} received", n=num)`` costs nearly nothing
    when filtered out, so debug statements can stay in the code permanently
    instead of being commented in and out during development.

Failures
    ``self._log.failure("wget transfer failed")`` replaces ``log.err``
    with explicit tracebacks attached as structured data.

The console renderer emits through a ``Logger`` as well (namespace
``cowrie.events``), so rendered event lines carry a namespace and level like
every other line and obey the same filtering.

Sequencing constraint: an ``eventid``-carrying ``log.msg`` must *not* be
converted to ``twisted.logger`` while plugins still observe the legacy
stream -- the adapter presents converted events with a different ``system``
view, the attribution regexes miss them, and the event is lost silently.
A file's diagnostics therefore convert only after its events have moved to
``EventLog``; the bulk of the sweep lands after the observers are gone
(phase 5). Files that emit no events can convert at any time.

Relationship to Twisted, and alternatives considered
****************************************************

Cowrie emits through Twisted's *legacy* logging API (``twisted.python.log``);
the attribution regexes parse that API's context prefixes. Twisted's own
answer to structured events is the modern ``twisted.logger`` package:
``Logger`` objects emitting keyword-structured events into observer chains,
with ``FilteringLogObserver`` and predicates for routing. Three alternatives
were considered against the proposed design:

``twisted.logger`` with a filtered observer
    Convert emitters to ``twisted.logger.Logger`` and register *one*
    observer that filters on ``eventid`` and fans out to plugins. This fixes
    the fan-out duplication (defect 4) idiomatically, but not attribution:
    ``twisted.logger`` has no bound context that survives a deferred hop, so
    the two-thirds of emitters that rely on execution context stay broken.
    It is the right modernization for Cowrie's *diagnostic* logging, which
    this plan adopts as phase 5.

``contextvars``
    Twisted (21.2+) runs deferred callbacks in the context captured when the
    callback was added, so a ``ContextVar`` holding the current session's
    emitter would follow download callbacks correctly with no explicit
    references. Rejected: every reactor entry point (``dataReceived``,
    ``connectionMade``, timers) must set the variable, and one missed entry
    point *misattributes* events silently. In a security event stream, a
    loud ``AttributeError`` on a missing ``self.events`` is preferable to
    quietly wrong data.

Status quo with patched tables
    Tombstoning the per-plugin session tables and guarding the lookups fixes
    the crashes but none of the attribution, duplication, or isolation
    defects.

The chosen design -- an explicit emitter object delivered through a single
publisher -- is not how Twisted routes its own logs, and that is deliberate:
security events are domain data with delivery guarantees, not diagnostics.
It does follow Twisted's shape where it matters: ``EventDispatcher`` is
structurally a domain-specific ``LogPublisher``, including its per-observer
error isolation, which Twisted's publisher has and Cowrie's current dispatch
loop lacks.

Operational considerations
**************************

No configuration changes
    Plugin selection, loading, and configuration are untouched;
    ``cowrie_plugin.py`` builds the same plugin list and hands it to the
    dispatcher instead of registering observers. An upgrade is a restart.

Plugin failure handling
    ``write()`` exceptions are caught per plugin. Error logging must be
    rate-limited per plugin (first failure, then periodic summaries): an
    unreachable database otherwise turns every attacker keystroke into an
    error line and floods ``cowrie.log``. Today the same outage aborts the
    dispatch loop mid-way, so plugins listed after the failing one silently
    lose the event.

Pipeline observability
    The dispatcher is one natural place to count events dispatched, events
    dropped, per-plugin deliveries, and per-plugin errors. Exposing these
    counters (to the prometheus plugin, or the status command) turns "is my
    ELK feed complete?" from guesswork into a metric. The current design has
    no such point; losses are invisible by construction.

Blocking plugins
    ``write()`` is called synchronously in the reactor thread, exactly as
    today -- a plugin doing blocking I/O stalls the honeypot either way. The
    dispatcher is the single place a delivery queue or thread pool could be
    added later; that change is deliberately out of scope here.

Shutdown
    Plugin ``stop()`` keeps its reactor shutdown trigger. The dispatcher
    tolerates dispatch-after-stop (drop and count) so a late deferred firing
    during shutdown cannot raise into the reactor teardown.

Log volume
    ``cowrie.log`` content is unchanged: one console line per event, plus
    diagnostics as before. Plugins stop scanning every Twisted log line, so
    per-event plugin work drops from (all log lines x N plugins) to
    (events x N plugins).

Security considerations
***********************

Audit-trail integrity
    Per-plugin error isolation means a plugin crash -- including one
    triggered by crafted attacker input -- can no longer suppress delivery
    of that event to the remaining plugins, and a plugin that raises no
    longer desynchronizes its private session table (there is none). Today
    both are possible, and the second is permanent for the process lifetime.

Attacker-controlled data
    Event fields (commands, URLs, filenames, version strings) are attacker
    input. The dispatcher's enrichment step is the single choke point where
    the *console* rendering can strip control characters and escape
    sequences (log-injection via ``\n`` or ANSI codes in a command line),
    while the structured event delivered to plugins keeps the raw bytes for
    forensics. Today every plugin and the console formatter each interpolate
    raw attacker strings independently.

Bounding late events
    Late events exist only while some live object (a pending deferred's
    command instance) still references the session's ``EventLog``; when the
    last reference is collected, no further events can be emitted for that
    session. The bound is therefore the lifetime of in-flight work, not wall
    time -- an attacker cannot keep a closed session emitting indefinitely
    without also keeping a transfer open, which existing timeouts already
    bound (treq ``timeout=10``, TFTP retry caps).

Event floods
    An attacker spamming commands generates events at line rate, unchanged
    from today. The dispatcher's counters provide the detection hook;
    rate-limiting event *generation* stays with the emitting subsystems
    (e.g. the download rate limiter).

Testing
*******

``EventLog`` and ``EventDispatcher`` are plain objects with no dependency on
the global Twisted log, so unit tests inject a capturing fake plugin and
assert on delivered dictionaries -- no log-observer fixtures, no regex
setup. Each phase-3 file conversion gets a test that the emitter delivers an
attributed event from a deferred context (the case the old pipeline fails).
The emit-site census (July 2026) doubles as the conversion checklist.

Migration plan
**************

The old and new pipelines can run side by side; an event travels exactly one
of them, so nothing is double-delivered.

Phase 1 -- introduce
    Add ``EventLog``, ``EventDispatcher``, and the console renderer;
    transports create the ``EventLog`` and keep emitting the old way. No
    behavior change (the renderer has nothing to render yet).

Phase 2 -- convert the bleeding edges
    Convert the download commands (wget, curl, tftp, ftpget, scp) and the
    other ``logDispatch`` call sites. This removes the dual-emission pattern
    and ends the loss of late download events -- the two defects with active
    production impact. The ``factory.logDispatch`` chain becomes unused and
    is removed.

Phase 3 -- sweep
    Convert the remaining ``log.msg(eventid=...)`` sites file by file
    (~45 files, mechanical). Each conversion moves that emitter from
    context-regex attribution to bound identity. ``cowrie.session.connect``
    and ``cowrie.session.closed`` are the one exception: they stay on the
    log path throughout this phase, because every plugin's ``emit()`` still
    builds its session table from ``connect`` -- converting them starves
    attribution for anything not yet converted (including the plugin-emitted
    enrichment events above). They convert atomically with phase 4. The
    public-key checker also stays legacy: Twisted constructs its credential
    object, so it carries no emitter.

Phase 4 -- delete
    Remove the ``log.addObserver(plugin.emit)`` registration, the regexes,
    the per-plugin tables, and the attribution half of ``Output.emit()``.
    Third-party plugins that only implement ``start``/``stop``/``write``
    are unaffected throughout; ones that override ``emit()`` or
    ``logDispatch()`` themselves would break here and must be checked for
    before this phase (none in-tree do).

Phase 5 -- modernize diagnostics
    Convert the remaining legacy ``log.msg`` / ``log.err`` call sites to
    per-class ``twisted.logger.Logger`` instances with namespaces and
    levels, and add per-namespace level filtering to the configuration.
    Safe to do wholesale only now: no consumer parses the log stream
    anymore, so the emitted ``system`` view is free to change. Files with
    no event emitters can convert earlier at will.

Open questions
**************

* Ordering: plugins currently see events in global log order. The dispatcher
  preserves per-session ordering trivially; is cross-session ordering worth
  guaranteeing? (No known consumer depends on it.)
* Whether ``sessionno`` should be dropped from the delivered event once
  nothing derives from it, or kept for operators who grep by transport
  number.
* Whether the dispatcher's counters ship in phase 1 (cheap, immediately
  useful for validating the migration itself) or as a follow-up.

.. |rarr| unicode:: 0x2192
