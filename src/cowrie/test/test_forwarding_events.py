# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Asserts direct-tcpip forwarding requests and discarded data
# ABOUTME: dispatch events through the session EventLog.

from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from twisted.conch.ssh import forwarding as conchforwarding

from cowrie.ssh import forwarding
from cowrie.test.eventcapture import capture_eventlog, events_of

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class ForwardingEventTests(unittest.TestCase):
    def test_request_dispatches_with_session_identity(self) -> None:
        events, dispatched = capture_eventlog(protocol="ssh")
        avatar = SimpleNamespace(
            conn=SimpleNamespace(transport=SimpleNamespace(events=events))
        )
        data = conchforwarding.packOpen_direct_tcpip(
            ("198.51.100.7", 443), ("10.0.0.1", 50000)
        )
        channel = forwarding.cowrieOpenConnectForwardingClient(
            262144, 32768, data, avatar
        )
        self.assertIsInstance(channel, forwarding.FakeForwardingChannel)

        requests = events_of(dispatched, "cowrie.direct-tcpip.request")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["dst_ip"], "198.51.100.7")
        self.assertEqual(requests[0]["dst_port"], 443)
        self.assertEqual(requests[0]["session"], "test0000")
        # The originator in the packet is attacker-controlled; it must not
        # replace the connection's source address.
        self.assertEqual(requests[0]["src_ip"], "1.2.3.4")
        self.assertEqual(requests[0]["orig_ip"], "10.0.0.1")
        self.assertEqual(requests[0]["orig_port"], 50000)

    def test_discarded_data_dispatches_with_session_identity(self) -> None:
        events, dispatched = capture_eventlog(protocol="ssh")
        channel = forwarding.FakeForwardingChannel(("198.51.100.7", 80))
        channel.conn = SimpleNamespace(transport=SimpleNamespace(events=events))
        channel.id = 0
        with patch.object(channel, "_close"):
            channel.dataReceived(b"GET / HTTP/1.0\r\n\r\n")

        data_events = events_of(dispatched, "cowrie.direct-tcpip.data")
        self.assertEqual(len(data_events), 1)
        self.assertEqual(data_events[0]["dst_port"], 80)
        self.assertEqual(data_events[0]["session"], "test0000")


if __name__ == "__main__":
    unittest.main()
