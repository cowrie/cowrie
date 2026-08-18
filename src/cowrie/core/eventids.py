# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The catalogue of event ids Cowrie emits, the single list every
# ABOUTME: emitter, consumer and docs section is checked against.

"""
The authoritative set of event ids.

An event id is part of Cowrie's published output contract: consumers match
on it, and the attributes each one carries are documented in
docs/OUTPUT.rst. Because both sides of that contract are plain strings
spread over emitters and output plugins, a typo is invisible until an
operator notices a plugin has quietly stopped reacting to an event.

``ALL`` is the pivot that makes such a typo a test failure:
``cowrie.test.test_eventids`` checks that every id emitted in the tree is
listed here, that every id an output plugin matches on is listed here, and
that docs/OUTPUT.rst documents exactly these ids and no others.

Adding an event means adding it here and documenting it in OUTPUT.rst.
"""

from __future__ import annotations

ALL: frozenset[str] = frozenset(
    {
        # AbuseIPDB reporting, operational rather than session-scoped
        "cowrie.abuseipdb.ratelimited",
        "cowrie.abuseipdb.reportedip",
        "cowrie.abuseipdb.reportfail",
        "cowrie.abuseipdb.started",
        "cowrie.abuseipdb.wakeup",
        # What the client told us about itself
        "cowrie.client.fingerprint",
        "cowrie.client.kex",
        "cowrie.client.malformed_packet",
        "cowrie.client.size",
        "cowrie.client.var",
        "cowrie.client.version",
        # Commands the attacker ran
        "cowrie.command.chpasswd",
        "cowrie.command.failed",
        "cowrie.command.input",
        "cowrie.command.success",
        # Port forwarding the attacker requested
        "cowrie.direct-tcpip.data",
        "cowrie.direct-tcpip.ja4",
        "cowrie.direct-tcpip.ja4h",
        "cowrie.direct-tcpip.redirect",
        "cowrie.direct-tcpip.request",
        "cowrie.direct-tcpip.tunnel",
        "cowrie.tunnelproxy-tcpip.data",
        # GreyNoise reputation lookups
        "cowrie.greynoise.result",
        # TTY session recordings
        "cowrie.log.closed",
        "cowrie.log.open",
        # Authentication
        "cowrie.login.failed",
        "cowrie.login.success",
        # Proxy backend plumbing
        "cowrie.proxy.backend_connect_error",
        "cowrie.proxy.backend_connected",
        "cowrie.proxy.backend_disconnected",
        "cowrie.proxy.client_disconnect",
        "cowrie.proxy.ssh",
        # Reverse DNS lookups
        "cowrie.reversedns.connect",
        "cowrie.reversedns.forward",
        # The connection and what passed through it
        "cowrie.session.closed",
        "cowrie.session.connect",
        "cowrie.session.file_download",
        "cowrie.session.file_download.failed",
        "cowrie.session.file_upload",
        "cowrie.session.input",
        "cowrie.session.params",
        # Telnet negotiation
        "cowrie.telnet.error",
        "cowrie.telnet.exploit_attempt",
        "cowrie.telnet.exploit_success",
        "cowrie.telnet.option",
        # VirusTotal lookups
        "cowrie.virustotal.scanfile",
        "cowrie.virustotal.scanurl",
    }
)
