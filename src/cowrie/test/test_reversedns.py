# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that the reversedns output plugin caches DNS results rather
# ABOUTME: than spent Deferreds, so repeat connects still dispatch (issue #40416).

from __future__ import annotations

import unittest
from unittest.mock import patch

from twisted.internet import defer
from twisted.names import dns, error

from cowrie.core.events import EventDispatcher
from cowrie.output.reversedns import Output
from cowrie.test.eventcapture import CaptureSink


def connect_event(src_ip: str) -> dict[str, str]:
    return {
        "eventid": "cowrie.session.connect",
        "session": "0000000000000000",
        "src_ip": src_ip,
        "protocol": "ssh",
    }


def forward_event(dst_ip: str) -> dict[str, str]:
    return {
        "eventid": "cowrie.direct-tcpip.request",
        "session": "0000000000000000",
        "src_ip": "9.9.9.9",
        "dst_ip": dst_ip,
        "protocol": "ssh",
    }


def ptr_result(
    name: str = "host.example.com", ttl: int = 3600
) -> tuple[list[dns.RRHeader], list, list]:
    payload = dns.Record_PTR(name=name, ttl=ttl)
    header = dns.RRHeader(
        name="4.3.2.1.in-addr.arpa", type=dns.PTR, payload=payload, ttl=ttl
    )
    return ([header], [], [])


class ReverseDnsCacheTests(unittest.TestCase):
    """The plugin must cache DNS results, not single-use Deferreds."""

    def setUp(self) -> None:
        self.output = Output()
        sink = CaptureSink()
        self.dispatched = sink.events
        self.output.dispatcher = EventDispatcher(
            [sink], logmsg=lambda *args, **kwargs: None
        )
        self.lookups: list[str] = []

    def patch_lookup(self, response):
        """Patch lookupPointer to record calls and return a fresh Deferred
        built by ``response`` on each call."""

        def fake_lookup(ptr, timeout=None):
            self.lookups.append(ptr)
            return response()

        return patch("cowrie.output.reversedns.client.lookupPointer", fake_lookup)

    def test_second_connect_same_ip_dispatches_again(self) -> None:
        with self.patch_lookup(lambda: defer.succeed(ptr_result())):
            self.output.write(connect_event("1.2.3.4"))
            self.output.write(connect_event("1.2.3.4"))
        self.assertEqual(len(self.lookups), 1)
        self.assertEqual(
            [e["eventid"] for e in self.dispatched],
            ["cowrie.reversedns.connect", "cowrie.reversedns.connect"],
        )
        self.assertEqual(self.dispatched[1]["ptr"], "host.example.com")

    def test_forward_after_connect_same_ip_dispatches(self) -> None:
        with self.patch_lookup(lambda: defer.succeed(ptr_result())):
            self.output.write(connect_event("1.2.3.4"))
            self.output.write(forward_event("1.2.3.4"))
        self.assertEqual(len(self.lookups), 1)
        self.assertEqual(
            [e["eventid"] for e in self.dispatched],
            ["cowrie.reversedns.connect", "cowrie.reversedns.forward"],
        )

    def test_nxdomain_is_cached(self) -> None:
        with self.patch_lookup(lambda: defer.fail(error.DNSNameError())):
            self.output.write(connect_event("1.2.3.4"))
            self.output.write(connect_event("1.2.3.4"))
        self.assertEqual(len(self.lookups), 1)
        self.assertEqual(self.dispatched, [])

    def test_timeout_is_not_cached(self) -> None:
        with self.patch_lookup(lambda: defer.fail(defer.TimeoutError())):
            self.output.write(connect_event("1.2.3.4"))
            self.output.write(connect_event("1.2.3.4"))
        self.assertEqual(len(self.lookups), 2)

    def test_servfail_is_not_cached(self) -> None:
        with self.patch_lookup(lambda: defer.fail(error.DNSServerError())):
            self.output.write(connect_event("1.2.3.4"))
            self.output.write(connect_event("1.2.3.4"))
        self.assertEqual(len(self.lookups), 2)

    def test_invalid_ip_does_no_lookup(self) -> None:
        with self.patch_lookup(lambda: defer.succeed(ptr_result())):
            self.output.write(connect_event("not-an-ip"))
        self.assertEqual(self.lookups, [])
        self.assertEqual(self.dispatched, [])

    def test_cache_is_bounded(self) -> None:
        self.output.cache_size = 2
        with self.patch_lookup(lambda: defer.succeed(ptr_result())):
            self.output.write(connect_event("1.1.1.1"))
            self.output.write(connect_event("2.2.2.2"))
            self.output.write(connect_event("3.3.3.3"))
            self.output.write(connect_event("1.1.1.1"))
        self.assertEqual(len(self.lookups), 4)


if __name__ == "__main__":
    unittest.main()
