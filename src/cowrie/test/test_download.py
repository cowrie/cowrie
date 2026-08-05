# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the shared machinery behind the file-fetching commands.
# ABOUTME: Covers rate-limiter construction and connecting to a pinned address.

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any
from unittest import mock
from unittest.mock import MagicMock

from twisted.internet import defer, reactor
from twisted.web.client import URI
from twisted.web.http_headers import Headers

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


class FakeResponse:
    def __init__(self, code: int = 200, location: str | None = None) -> None:
        self.code = code
        self.headers = Headers()
        if location is not None:
            self.headers.setRawHeaders("location", [location])


class TestFetch(unittest.TestCase):
    """Every hop of a fetch is validated and connected to by address."""

    def setUp(self) -> None:
        self.validated: list[str] = []
        self.requested: list[tuple[str, str]] = []
        self.responses: list[FakeResponse] = []

        def fake_resolve(host: str) -> Any:
            self.validated.append(host)
            return defer.succeed(None if host.startswith("blocked") else "203.0.113.9")

        def fake_get(url: str, agent: Any = None, **kwargs: Any) -> Any:
            self.requested.append((url, agent._endpointFactory._address))
            return defer.succeed(self.responses.pop(0))

        for target, attr in ((download, "resolve_allowed"), (download.treq, "get")):
            patcher = mock.patch.object(
                target, attr, fake_resolve if attr == "resolve_allowed" else fake_get
            )
            patcher.start()
            self.addCleanup(patcher.stop)

    def _fetch(self, url: str) -> Any:
        result: list[Any] = []
        failure: list[Any] = []
        download.fetch(reactor, url).addCallbacks(result.append, failure.append)
        return result, failure

    def test_returns_the_response_for_a_direct_hit(self) -> None:
        self.responses = [FakeResponse()]

        _result, failure = self._fetch("http://example.invalid/payload")

        self.assertFalse(failure)
        self.assertEqual(self.validated, ["example.invalid"])
        self.assertEqual(
            self.requested, [("http://example.invalid/payload", "203.0.113.9")]
        )

    def test_blocked_host_is_refused(self) -> None:
        result, failure = self._fetch("http://blocked.invalid/payload")

        self.assertFalse(result)
        self.assertIsInstance(failure[0].value, download.BlockedAddress)

    def test_each_redirect_hop_is_validated(self) -> None:
        # An agent that follows redirects itself would reach the new location
        # unchecked, which is how a public URL smuggles you to a private one.
        self.responses = [
            FakeResponse(302, "http://blocked.invalid/inner"),
            FakeResponse(),
        ]

        result, failure = self._fetch("http://example.invalid/payload")

        self.assertFalse(result)
        self.assertIsInstance(failure[0].value, download.BlockedAddress)
        self.assertEqual(self.validated, ["example.invalid", "blocked.invalid"])

    def test_relative_redirect_resolves_against_the_current_url(self) -> None:
        self.responses = [FakeResponse(302, "/second"), FakeResponse()]

        _result, failure = self._fetch("http://example.invalid/first")

        self.assertFalse(failure)
        self.assertEqual(
            [url for url, _ in self.requested],
            ["http://example.invalid/first", "http://example.invalid/second"],
        )

    def test_redirect_is_returned_when_not_following(self) -> None:
        # curl reports a redirect rather than following it, so the response
        # must come back instead of being treated as an over-long chain.
        self.responses = [FakeResponse(302, "http://elsewhere.invalid/x")]

        collected: list[Any] = []
        failure: list[Any] = []
        download.fetch(
            reactor, "http://example.invalid/x", max_redirects=0
        ).addCallbacks(collected.append, failure.append)

        self.assertFalse(failure)
        self.assertEqual(collected[0].code, 302)
        self.assertEqual(self.validated, ["example.invalid"])

    def test_redirect_loop_gives_up(self) -> None:
        self.responses = [FakeResponse(302, "http://example.invalid/x")] * 10

        result, failure = self._fetch("http://example.invalid/x")

        self.assertFalse(result)
        self.assertIsInstance(failure[0].value, download.TooManyRedirects)


if __name__ == "__main__":
    unittest.main()
