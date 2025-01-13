from typing import Any
from collections.abc import Generator
from twisted.internet.defer import inlineCallbacks, Deferred
import ipaddress
from twisted.names import client

# Blocked IPs list (example)
BLOCKED_IPS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.169.254",  # Cloud metadata IPs
    "100.100.100.200",  # Alibaba Cloud metadata
]


@inlineCallbacks
def communication_allowed(address: str) -> Generator[Deferred[Any], Any, bool]:
    """
    Return whether or not communication to this address is allowed.
    This can take IPv4, IPv6 addresses, or a DNS name. DNS will be resolved if necessary.
    """
    # First check if the address is already a valid IP address
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        # If not an IP, resolve it as a DNS name
        try:
            answers, _, _ = yield client.lookupAddress(address)
            resolved_ip = answers[0].payload.dottedQuad()
        except Exception:
            # If DNS resolution fails, treat it as not allowed
            return False
    else:
        # If it's an IP, use it directly
        resolved_ip = str(ip)

    # Check if the resolved IP is in the blocked list
    try:
        ip = ipaddress.ip_address(resolved_ip)
        for blocked in BLOCKED_IPS:
            if ip in ipaddress.ip_network(blocked, strict=False):
                return False
    except ValueError:
        # If IP parsing fails, treat it as not allowed
        return False

    # Allow communication if all checks pass
    return True
