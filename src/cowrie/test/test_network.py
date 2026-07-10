# SPDX-FileCopyrightText: 2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

import unittest
from collections.abc import Callable
from typing import Any
from unittest import mock

from twisted.internet.defer import Deferred, fail, inlineCallbacks, succeed
from twisted.names import dns
from twisted.names import error as names_error
from twisted.python import log

from cowrie.core.network import communication_allowed, resolve_cname

# The communication_allowed function and other dependencies would already be imported here


class TestCommunicationAllowed(unittest.TestCase):
    def setUp(self):
        # Setup code, if needed
        self.blocked_ips = [
            "10.0.0.0/8",  # Private IP range 10.0.0.0 - 10.255.255.255
            "172.16.0.0/12",  # Private IP range 172.16.0.0 - 172.31.255.255
            "192.168.0.0/16",  # Private IP range 192.168.0.0 - 192.168.255.255
            "169.254.169.254",  # Cloud metadata IP (AWS, GCP, etc.)
            "100.100.100.200",  # Alibaba Cloud metadata IP
            "127.0.0.0/8",  # Loopback addresses (localhost)
            "0.0.0.0/8",  # Reserved IP range
            "224.0.0.0/4",  # Multicast addresses
            "240.0.0.0/4",  # Reserved addresses
            "255.255.255.255",  # Limited broadcast address
        ]

    @inlineCallbacks
    def test_ipv4_address_allowed(self):
        # Test with a non-blocked IPv4 address (should return True)
        allowed = yield communication_allowed("8.8.8.8")  # Google's public DNS
        self.assertTrue(allowed)

    @inlineCallbacks
    def test_ipv4_address_blocked(self):
        # Test with a blocked IPv4 address (should return False)
        allowed = yield communication_allowed(
            "10.1.1.1"
        )  # Example from blocked range 10.0.0.0/8
        self.assertFalse(allowed)

    @inlineCallbacks
    def test_ipv6_address_allowed(self):
        # Test with a non-blocked IPv6 address (should return True)
        allowed = yield communication_allowed("2001:4860:4860::8888")  # Google's IPv6
        self.assertTrue(allowed)

    @inlineCallbacks
    def test_ipv6_address_blocked(self):
        # Test with a blocked IPv6 address (should return False)
        allowed = yield communication_allowed("::1")  # Loopback address
        self.assertFalse(allowed)

    @inlineCallbacks
    def test_dns_resolution_allowed(self):
        # Test with a resolvable DNS address that points to a non-blocked IP
        allowed = yield communication_allowed("example.com")
        self.assertTrue(allowed)

    @inlineCallbacks
    def test_dns_resolution_blocked(self):
        # Test with a DNS address that resolves to a blocked IP
        allowed = yield communication_allowed("localhost")  # Resolves to 127.0.0.1
        self.assertFalse(allowed)

    @inlineCallbacks
    def test_invalid_ip_address(self):
        # Test with an invalid IP address (should return False)
        allowed = yield communication_allowed("999.999.999.999")
        self.assertFalse(allowed)

    @inlineCallbacks
    def test_cname_resolution(self):
        # Test with a CNAME that resolves to an allowed IP
        allowed = yield communication_allowed("www.google.com")
        self.assertTrue(allowed)

    @inlineCallbacks
    def test_cname_resolution_blocked(self):
        # Test with a CNAME that resolves to a blocked IP (e.g., 127.0.0.1)
        allowed = yield communication_allowed("localhost")  # Should be blocked
        self.assertFalse(allowed)


def _fake_lookup(
    records: dict[str, list[dns.RRHeader]],
) -> Callable[[Any], Deferred]:
    """A lookupAddress double serving canned answers. It enforces the same
    argument contract as twisted's resolver: only str or bytes are accepted."""

    def lookup(name: Any) -> Deferred:
        if not isinstance(name, (bytes, str)):
            raise TypeError(type(name).__name__)
        if name in records:
            return succeed((records[name], [], []))
        return fail(names_error.DNSNameError(name))

    return lookup


def _cname(target: str) -> dns.RRHeader:
    return dns.RRHeader(type=dns.CNAME, payload=dns.Record_CNAME(target.encode()))


def _a(address: str) -> dns.RRHeader:
    return dns.RRHeader(type=dns.A, payload=dns.Record_A(address))


def _aaaa(address: str) -> dns.RRHeader:
    return dns.RRHeader(type=dns.AAAA, payload=dns.Record_AAAA(address))


class TestResolveCnameChain(unittest.TestCase):
    """resolve_cname must follow CNAME chains to the final address record
    (issue #40283) and read AAAA records with the IPv6 API."""

    def _resolve(self, records: dict[str, list[dns.RRHeader]], name: str) -> str | None:
        with mock.patch(
            "cowrie.core.network.client.lookupAddress",
            side_effect=_fake_lookup(records),
        ):
            results: list[str | None] = []
            resolve_cname(name, set()).addBoth(results.append)
        self.assertEqual(len(results), 1)
        return results[0]

    def test_cname_chain_resolves_to_a_record(self) -> None:
        records = {
            "cdn.example.com": [_cname("edge.example.net")],
            "edge.example.net": [_cname("origin.example.org")],
            "origin.example.org": [_a("203.0.113.7")],
        }
        self.assertEqual(self._resolve(records, "cdn.example.com"), "203.0.113.7")

    def test_aaaa_record_resolves(self) -> None:
        records = {"v6.example.com": [_aaaa("2001:db8::1")]}
        self.assertEqual(self._resolve(records, "v6.example.com"), "2001:db8::1")

    def test_cname_cycle_returns_none(self) -> None:
        records = {
            "a.example.com": [_cname("b.example.com")],
            "b.example.com": [_cname("a.example.com")],
        }
        self.assertIsNone(self._resolve(records, "a.example.com"))


class TestResolveCnameLogging(unittest.TestCase):
    """A failed DNS lookup is handled, so it must not be logged as an error."""

    def test_failed_lookup_logged_without_unhandled_error(self) -> None:
        events: list[dict] = []
        log.addObserver(events.append)
        try:
            failed = fail(names_error.DNSNameError("bin"))
            with mock.patch(
                "cowrie.core.network.client.lookupAddress", return_value=failed
            ):
                results: list = []
                resolve_cname("bin", set()).addBoth(results.append)
        finally:
            log.removeObserver(events.append)

        # The lookup fails synchronously, so resolve_cname returns None.
        self.assertEqual(results, [None])
        # log.err marks events with isError=1 and prints "Unhandled Error"; the
        # caught failure must instead be an informational message.
        self.assertFalse(any(e.get("isError") for e in events))
        messages = [log.textFromEventDict(e) or "" for e in events]
        self.assertTrue(any("DNS lookup failed for 'bin'" in m for m in messages))


if __name__ == "__main__":
    unittest.main()
