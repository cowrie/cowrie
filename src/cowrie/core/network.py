from twisted.internet.defer import inlineCallbacks, Deferred
from twisted.names import client, dns
import ipaddress
from typing import Generator, List, Optional, Set, Union

BLOCKED_IPS = [
    "10.0.0.0/8",           # Private IP range 10.0.0.0 - 10.255.255.255
    "172.16.0.0/12",        # Private IP range 172.16.0.0 - 172.31.255.255
    "192.168.0.0/16",       # Private IP range 192.168.0.0 - 192.168.255.255
    "169.254.169.254",      # Cloud metadata IP (usually for AWS, GCP, etc.)
    "100.100.100.200",      # Alibaba Cloud metadata IP
    "127.0.0.0/8",          # Loopback addresses (localhost)
    "0.0.0.0/8",            # This is a reserved IP range
    "224.0.0.0/4",          # Multicast addresses
    "240.0.0.0/4",          # Reserved addresses
    "255.255.255.255"       # Limited broadcast address
]

def is_ip_address(address: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """
    Returns an IPv4 or IPv6 address if the string is a valid IP, otherwise returns None.
    """
    try:
        # Try to create an IP address object (both IPv4 and IPv6 supported)
        return ipaddress.ip_address(address)
    except ValueError:
        return None

@inlineCallbacks
def resolve_cname(address: str, visited: Set[str]) -> Generator[Deferred, None, Optional[str]]:
    """
    Resolve a CNAME record recursively and return the final resolved IP address (either IPv4 or IPv6)
    or None if not resolvable. `visited` is a set that tracks the domains we've already resolved to prevent cycles.
    """
    # Prevent cyclic resolution (avoid infinite loops)
    if address in visited:
        return None

    visited.add(address)

    try:
        # Look up the DNS records for the address
        result: Optional[List[dns.RRHeader]] = yield client.lookupAddress(address)
        if result:
            # Iterate through the DNS records to find CNAME or A/AAAA record
            for rr in result:
                if isinstance(rr.payload, dns.Record_CNAME):
                    # It's a CNAME, resolve the target domain recursively
                    resolved_ip = yield resolve_cname(rr.payload.name, visited)
                    if resolved_ip:
                        return resolved_ip
                elif isinstance(rr.payload, dns.Record_A):
                    # We found an A record (IPv4 address), return it immediately
                    return str(rr.payload.dottedQuad())
                elif isinstance(rr.payload, dns.Record_AAAA):
                    # We found an AAAA record (IPv6 address), return it immediately
                    return str(rr.payload.dottedQuad())
    except Exception:
        return None  # In case of any failure, return None

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
        visited: Set[str] = set()  # To track visited domains and prevent cycles
        result = yield resolve_cname(address, visited)

        # If no IP was resolved, it's not allowed
        if result is None:
            return False
        else:
           resolved_ip = result

    # At this point, resolved_ip should always be a valid string (IPv4 or IPv6)
    try:
        ip = ipaddress.ip_address(resolved_ip)

        # Check if the resolved IP falls within any blocked IP ranges
        for blocked in BLOCKED_IPS:
            if ip in ipaddress.ip_network(blocked, strict=False):
                return False  # Blocked IP found
    except ValueError:
        return False  # If the resolved IP is not a valid IP address, return False

    return True  # Communication is allowed
