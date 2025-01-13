from twisted.internet import defer

from twisted.internet.defer import inlineCallbacks
from twisted.names import client
import ipaddress

# Define a list of blocked IPs or subnets
BLOCKED_IPS = [
    # Private IP Ranges
    "10.0.0.0/8",  # Private IPv4 subnet
    "172.16.0.0/12",  # Private IPv4 subnet
    "192.168.0.0/16",  # Private IPv4 subnet
    # Loopback Addresses
    "127.0.0.0/8",  # IPv4 loopback range
    "::1",  # IPv6 loopback
    # Link-Local Addresses
    "169.254.0.0/16",  # IPv4 link-local
    "fe80::/10",  # IPv6 link-local
    # Multicast and Broadcast Addresses
    "224.0.0.0/4",  # IPv4 multicast
    "ff00::/8",  # IPv6 multicast
    "255.255.255.255",  # IPv4 broadcast
    # Cloud Metadata IPs
    "169.254.169.254",  # Cloud metadata (AWS, Azure, GCP, Oracle, etc.)
    "100.100.100.200",  # Alibaba Cloud metadata
    # Reserved and Special-Use IP Ranges
    "0.0.0.0/8",  # IPv4 unspecified
    "240.0.0.0/4",  # IPv4 reserved
    "::/128",  # IPv6 unspecified
    "fc00::/7",  # IPv6 unique local address range
]


from typing import Generator, Any
from twisted.internet.defer import inlineCallbacks, Deferred


@inlineCallbacks
def communication_allowed(address: str) -> Generator[Deferred[Any], Any, bool]:
    """
    Return whether or not communication to this address is allowed.
    This can take IPv4, IPv6 address, or a DNS name. DNS will be resolved using Twisted.
    """
    try:
        # Resolve the address to an IP using Twisted's DNS client
        answers, _, _ = yield client.lookupAddress(address)
        resolved_ip = answers[0].payload.dottedQuad()
    except Exception:
        # If DNS resolution fails, treat it as not allowed
        return False

    # Check if resolved IP is in blocked IPs
    try:
        ip = ipaddress.ip_address(resolved_ip)
        for blocked in BLOCKED_IPS:
            if ip in ipaddress.ip_network(blocked, strict=False):
                return False
    except ValueError:
        # Invalid IP address
        return False

    # Allow communication if it passes all checks
    return True
