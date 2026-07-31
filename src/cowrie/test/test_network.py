# SPDX-FileCopyrightText: 2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

import unittest
from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from unittest import mock

from twisted.internet.defer import Deferred, fail, succeed
from twisted.names import dns
from twisted.names import error as names_error
from twisted.python import log

if TYPE_CHECKING:
    from twisted.python.failure import Failure

from cowrie.core.network import (
    communication_allowed,
    resolve_allowed,
    resolve_cname,
)


class TestCommunicationAllowed(unittest.TestCase):
    """communication_allowed validates IP literals synchronously against the
    blocklist; hostnames go through resolve_allowed, which is tested below
    with a canned resolver, so no test here touches real DNS."""

    def _allowed(self, address: str) -> bool:
        with mock.patch(
            "cowrie.core.network.client.lookupAddress",
            side_effect=_fake_lookup({}),
        ):
            results: list[bool | Failure] = []
            communication_allowed(address).addBoth(results.append)
        self.assertEqual(len(results), 1)
        value = results[0]
        self.assertIsInstance(value, bool)
        assert isinstance(value, bool)
        return value

    def test_public_addresses_allowed(self) -> None:
        for address in (
            "8.8.8.8",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",  # IPv4-mapped public address stays allowed
        ):
            with self.subTest(address=address):
                self.assertTrue(self._allowed(address))

    def test_blocked_addresses(self) -> None:
        for address in (
            "10.1.1.1",  # private range 10.0.0.0/8
            "100.64.0.1",  # carrier-grade NAT, not globally routable
            "198.18.0.1",  # benchmarking space, not globally routable
            "::1",  # IPv6 loopback
            "fe80::1",  # IPv6 link-local
            "fc00::1",  # IPv6 unique-local
            "::ffff:127.0.0.1",  # IPv4-mapped loopback
            "::ffff:169.254.169.254",  # IPv4-mapped cloud metadata IP
            "::127.0.0.1",  # IPv4-compatible loopback (deprecated ::a.b.c.d)
            "2002:a00:101::",  # 6to4 embedding private 10.0.1.1
            "64:ff9b::7f00:1",  # NAT64 embedding loopback 127.0.0.1
        ):
            with self.subTest(address=address):
                self.assertFalse(self._allowed(address))

    def test_invalid_ip_treated_as_unresolvable(self) -> None:
        # Not a valid IP literal, so it takes the DNS path; the canned
        # resolver has no records for it, so communication is refused.
        self.assertFalse(self._allowed("999.999.999.999"))


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


class TestResolveAllowed(unittest.TestCase):
    """resolve_allowed must resolve a target once, validate that exact IP,
    and hand the pinned IP back to the caller, so the address that was
    validated is the same one the caller connects to (no DNS-rebinding
    window between validation and connect)."""

    def _resolve(
        self, records: dict[str, list[dns.RRHeader]], name: str
    ) -> str | None:
        with mock.patch(
            "cowrie.core.network.client.lookupAddress",
            side_effect=_fake_lookup(records),
        ):
            results: list[str | None] = []
            resolve_allowed(name).addBoth(results.append)
        self.assertEqual(len(results), 1)
        return results[0]

    def test_public_ip_passes_through(self) -> None:
        self.assertEqual(self._resolve({}, "8.8.8.8"), "8.8.8.8")

    def test_blocked_ip_returns_none(self) -> None:
        self.assertIsNone(self._resolve({}, "10.1.1.1"))

    def test_hostname_resolves_to_pinned_ip(self) -> None:
        records = {"dl.example.com": [_a("8.8.4.4")]}
        self.assertEqual(self._resolve(records, "dl.example.com"), "8.8.4.4")

    def test_hostname_resolving_to_blocked_ip_returns_none(self) -> None:
        records = {"rebind.example.com": [_a("127.0.0.1")]}
        self.assertIsNone(self._resolve(records, "rebind.example.com"))

    def test_unresolvable_hostname_returns_none(self) -> None:
        self.assertIsNone(self._resolve({}, "nonexistent.example.com"))

    def test_cname_chain_resolves_to_pinned_ip(self) -> None:
        records = {
            "cdn.example.com": [_cname("origin.example.org")],
            "origin.example.org": [_a("8.8.8.8")],
        }
        self.assertEqual(self._resolve(records, "cdn.example.com"), "8.8.8.8")


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
