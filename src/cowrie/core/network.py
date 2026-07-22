# SPDX-FileCopyrightText: 2025-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

import ipaddress
import re
import socket
from collections.abc import Generator

from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.logger import Logger
from twisted.names import client, dns

_log = Logger()

BLOCKED_IPS = [
    "0.0.0.0/8",  # Current IP range 0.0.0.0 - 10.255.255.255
    "10.0.0.0/8",  # Private IP range 10.0.0.0 - 10.255.255.255
    "172.16.0.0/12",  # Private IP range 172.16.0.0 - 172.31.255.255
    "192.168.0.0/16",  # Private IP range 192.168.0.0 - 192.168.255.255
    "169.254.0.0/16",  # Cloud metadata IP (usually for AWS, GCP, etc.)
    "100.100.100.200",  # Alibaba Cloud metadata IP
    "127.0.0.0/8",  # Loopback addresses (localhost)
    "0.0.0.0/8",  # This is a reserved IP range
    "224.0.0.0/4",  # Multicast addresses
    "240.0.0.0/4",  # Reserved addresses
    "255.255.255.255",  # Limited broadcast address
    "::1",  # IPv6 loopback
    "fe80::/10",  # IPv6 link-local
    "fc00::/7",  # IPv6 unique-local (private)
    "ff00::/8",  # IPv6 multicast
]

# NAT64 well-known prefix (RFC 6052): 64:ff9b::/96 embeds an IPv4 address in
# its low 32 bits, just like an IPv4-mapped address does.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")

# IPv4-compatible prefix (::a.b.c.d, deprecated by RFC 4291): also embeds an
# IPv4 address in its low 32 bits. ::/96 also contains ::1 and ::, whose
# embedded 0.0.0.x values are non-global and stay blocked.
_IPV4_COMPATIBLE_PREFIX = ipaddress.ip_network("::/96")


def _embedded_ipv4(
    ip: ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """
    Return the IPv4 address embedded in an IPv6 address, or None if there is
    none. Covers IPv4-mapped (``::ffff:0:0/96``), 6to4 (``2002::/16``), NAT64
    (``64:ff9b::/96``), and IPv4-compatible (``::/96``) forms, all of which can
    reach an IPv4 target through an IPv6 wrapper.
    """
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip.sixtofour is not None:
        return ip.sixtofour
    if ip in _NAT64_PREFIX or ip in _IPV4_COMPATIBLE_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    Return True if the address must not be contacted. An IPv6 address that
    embeds an IPv4 address is also checked as that IPv4 address, so a private
    or metadata target cannot be reached through an IPv6 wrapper.

    A candidate is blocked if it is not globally routable or if it falls
    within an explicit blocked range. The explicit list stays authoritative
    for targets that are not globally routable yet not covered by is_global
    (e.g. the Alibaba metadata IP) and guards against interpreter versions
    whose is_global misclassifies IPv4-mapped addresses.
    """
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            candidates.append(embedded)

    for candidate in candidates:
        if not candidate.is_global:
            return True
        for blocked in BLOCKED_IPS:
            if candidate in ipaddress.ip_network(blocked, strict=False):
                return True
    return False


# Valid TCP/UDP port range: 1-65535
# https://www.debuggex.com/r/jjEFZZQ34aPvCBMA
PORT_PATTERN = re.compile(
    r"^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$"
)


def is_valid_port(port: str) -> bool:
    """Check if port string is a valid TCP/UDP port number (1-65535)"""
    return bool(PORT_PATTERN.match(port))


def is_ip_address(
    address: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """
    Returns an IPv4 or IPv6 address if the string is a valid IP, otherwise returns None.
    """
    try:
        # Try to create an IP address object (both IPv4 and IPv6 supported)
        return ipaddress.ip_address(address)
    except ValueError:
        return None


@inlineCallbacks
def resolve_cname(
    address: str, visited: set[str]
) -> Generator[Deferred, None, str | None]:
    """
    Resolve a CNAME record recursively and return the final resolved IP address (either IPv4 or IPv6)
    or None if not resolvable. `visited` is a set that tracks the domains we've already resolved to prevent cycles.
    """

    _log.debug("resolve_cname({address})", address=address)

    # Prevent cyclic resolution (avoid infinite loops)
    if address in visited:
        return None

    visited.add(address)

    try:
        # Look up the DNS records for the address
        result = yield client.lookupAddress(address)
        if result:
            headers: list[dns.RRHeader] = result[0]  # type: ignore
            # Iterate through the DNS records to find CNAME or A/AAAA record
            for rr in headers:
                if isinstance(rr.payload, dns.Record_CNAME):
                    # It's a CNAME, resolve the target domain recursively.
                    # rr.payload.name is a dns.Name; lookupAddress only accepts
                    # str or bytes, and the visited set holds str.
                    resolved_ip = yield resolve_cname(str(rr.payload.name), visited)
                    if resolved_ip:
                        return resolved_ip
                elif isinstance(rr.payload, dns.Record_A):
                    # We found an A record (IPv4 address), return it immediately
                    return str(rr.payload.dottedQuad())
                elif isinstance(rr.payload, dns.Record_AAAA):
                    # We found an AAAA record (IPv6 address), return it
                    # immediately. Record_AAAA has no dottedQuad(); its
                    # address field holds the packed 16-byte value.
                    return socket.inet_ntop(socket.AF_INET6, rr.payload.address)
    except Exception as e:
        # A failed lookup (NXDOMAIN for an attacker's single-word hostname, a
        # timeout, ...) is routine and handled here by returning None. Log it at
        # informational level; log.err would format it as an "Unhandled Error"
        # with a traceback, which is misleading for a caught exception.
        _log.info(
            "DNS lookup failed for {address!r}: {error}", address=address, error=e
        )
        return None  # In case of any failure, return None

    _log.info("no valid a or cname record")
    return None  # No valid A or CNAME records were found


@inlineCallbacks
def communication_allowed(address: str) -> Generator[Deferred, None, bool]:
    """
    Return True if communication to this address is allowed, False if blocked (for both IPs and DNS names).
    """
    # First, check if it's already a valid IP address (either IPv4 or IPv6)
    ip = is_ip_address(address)

    if ip is not None:
        resolved_ip: str = str(ip)
    else:
        # Resolve the DNS name and follow CNAME resolution
        visited: set[str] = set()  # To track visited domains and prevent cycles
        result = yield resolve_cname(address, visited)

        # If no IP was resolved, it's not allowed
        if result is None:
            return False
        else:
            resolved_ip = result  # type: ignore

    # At this point, resolved_ip should always be a valid string (IPv4 or IPv6)
    try:
        ip = ipaddress.ip_address(resolved_ip)
    except ValueError:
        return False  # If the resolved IP is not a valid IP address, return False

    if _is_blocked(ip):
        return False  # Blocked IP found

    return True  # Communication is allowed
