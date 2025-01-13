import unittest

from twisted.internet.defer import inlineCallbacks

from cowrie.core.network import communication_allowed

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


if __name__ == "__main__":
    unittest.main()
