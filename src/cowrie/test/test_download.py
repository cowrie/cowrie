# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the shared machinery behind the file-fetching commands.
# ABOUTME: Covers rate-limiter construction and connecting to a pinned address.

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import MagicMock

from twisted.internet import reactor
from twisted.web.client import URI

from cowrie.core import download
from cowrie.core.config import CowrieConfig

os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()


class TestOutboundRateLimiter(unittest.TestCase):
    """Every fetching command reads the same four settings under its own name."""

    def test_reads_the_commands_own_settings(self) -> None:
        CowrieConfig.read_string(
            "[shell]\n"
            "wget_rate_limit_requests = 7\n"
            "wget_rate_limit_window = 30\n"
            "wget_rate_limit_max_hosts = 12\n"
        )
        self.addCleanup(CowrieConfig.remove_section, "shell")

        limiter = download.outbound_rate_limiter("wget")

        self.assertTrue(limiter.enabled)
        self.assertEqual(limiter.max_requests, 7)
        self.assertEqual(limiter.window_seconds, 30)
        self.assertEqual(limiter.max_keys, 12)

    def test_defaults_when_unconfigured(self) -> None:
        limiter = download.outbound_rate_limiter("tftp")

        self.assertTrue(limiter.enabled)
        self.assertEqual(limiter.max_requests, 5)
        self.assertEqual(limiter.window_seconds, 60)
        self.assertEqual(limiter.max_keys, 1000)


class TestPinnedAgent(unittest.TestCase):
    """HTTP requests must go to the validated address, not re-resolve the name."""

    def test_connects_to_the_pinned_address(self) -> None:
        # Re-resolving at connect time lets a malicious server answer the
        # validation lookup with a public IP and the connection lookup with
        # a private one.
        agent = download.pinned_agent(reactor, "203.0.113.9")

        endpoint = agent._endpointFactory.endpointForURI(
            URI.fromBytes(b"http://example.invalid/payload")
        )

        self.assertEqual(endpoint._hostText, "203.0.113.9")
        self.assertEqual(endpoint._port, 80)

    def test_https_still_negotiates_tls_for_the_hostname(self) -> None:
        # The pinned address is only where we connect; TLS verification and
        # SNI still belong to the name the attacker asked for, so the
        # endpoint must stay wrapped rather than becoming a bare connection.
        agent = download.pinned_agent(reactor, "203.0.113.9")

        endpoint = agent._endpointFactory.endpointForURI(
            URI.fromBytes(b"https://example.invalid/payload")
        )

        inner = endpoint._wrappedEndpoint
        self.assertEqual(inner._hostText, "203.0.113.9")
        self.assertEqual(inner._port, 443)

    def test_tls_is_negotiated_for_the_requested_hostname(self) -> None:
        # Certificate validation and SNI must use the hostname; pinning the
        # address must not downgrade them to the bare IP.
        policy = MagicMock()
        agent = download.pinned_agent(reactor, "203.0.113.9", policy=policy)

        agent._endpointFactory.endpointForURI(
            URI.fromBytes(b"https://example.invalid/payload")
        )

        policy.creatorForNetloc.assert_called_once_with(b"example.invalid", 443)


if __name__ == "__main__":
    unittest.main()
