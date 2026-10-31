# SPDX-FileCopyrightText: 2026 sudu787
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that both ends of the backend pool protocol handle messages
# ABOUTME: split across reads or sent together in one read (TCP is a stream).

from __future__ import annotations

import struct
import unittest
from unittest.mock import MagicMock

from twisted.internet.testing import StringTransport

from backend_pool.pool_server import PoolServer
from cowrie.pool_interface.client import PoolClient
from cowrie.test.configoverride import override_option


def _vm_response(guest_id: int, ip: bytes, ssh: int, telnet: int, snap: bytes) -> bytes:
    fmt = f"!cIIH{len(ip)}sHHH{len(snap)}s"
    return struct.pack(
        fmt, b"r", 0, guest_id, len(ip), ip, ssh, telnet, len(snap), snap
    )


class PoolServerFramingTests(unittest.TestCase):
    def setUp(self) -> None:
        override_option(self, "backend_pool", "use_nat", "false")
        self.factory = MagicMock()
        self.factory.pool_service.request_vm.return_value = (7, "10.0.0.7", "snap")
        self.server = PoolServer(self.factory)
        self.wire = StringTransport()
        self.server.makeConnection(self.wire)

    def feed(self, data: bytes, step: int | None = None) -> None:
        step = step or len(data)
        for i in range(0, len(data), step):
            self.server.dataReceived(data[i : i + step])

    def test_request_split_across_reads(self) -> None:
        self.feed(struct.pack("!cII?", b"i", 3, 600, True), step=1)
        self.factory.pool_service.set_configs.assert_called_once_with(3, 600, True)
        self.assertEqual(self.wire.value(), struct.pack("!cI", b"i", 0))

    def test_requests_in_one_read(self) -> None:
        self.feed(struct.pack("!cI", b"f", 1) + struct.pack("!cI", b"u", 2))
        self.factory.pool_service.free_vm.assert_called_once_with(1)
        self.factory.pool_service.reuse_vm.assert_called_once_with(2)

    def test_variable_length_request_split_across_reads(self) -> None:
        ip = b"203.0.113.9"
        self.feed(struct.pack(f"!cH{len(ip)}s", b"r", len(ip), ip), step=2)
        self.factory.pool_service.request_vm.assert_called_once_with("203.0.113.9")
        self.assertTrue(self.wire.value().startswith(struct.pack("!cII", b"r", 0, 7)))

    def test_unknown_op_code_drops_the_connection(self) -> None:
        self.feed(b"zzzz")
        self.assertTrue(self.wire.disconnecting)
        self.factory.pool_service.free_vm.assert_not_called()


class PoolClientFramingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = PoolClient(MagicMock())
        self.parent = MagicMock()
        self.client.set_parent(self.parent)
        self.wire = StringTransport()
        self.client.makeConnection(self.wire)

    def test_vm_response_split_across_reads(self) -> None:
        data = _vm_response(7, b"10.0.0.7", 22, 23, b"/snap/a.qcow2")
        for i in range(len(data)):
            self.client.dataReceived(data[i : i + 1])
        self.parent.received_pool_data.assert_called_once_with(
            b"r", 0, b"10.0.0.7", b"/snap/a.qcow2", 22, 23
        )
        self.assertEqual(self.client.vm_id, 7)

    def test_responses_in_one_read(self) -> None:
        data = struct.pack("!cI", b"i", 0) + _vm_response(5, b"::1", 2222, 2323, b"")
        self.client.dataReceived(data)
        self.parent.initialisation_response.assert_called_once_with(0)
        self.parent.received_pool_data.assert_called_once_with(
            b"r", 0, b"::1", b"", 2222, 2323
        )

    def test_error_response_is_five_bytes(self) -> None:
        # A failed VM request carries no body; the next response follows it.
        data = struct.pack("!cI", b"r", 1) + struct.pack("!cI", b"i", 0)
        self.client.dataReceived(data)
        self.parent.loseConnection.assert_called_once_with()
        self.parent.initialisation_response.assert_called_once_with(0)

    def test_unknown_op_code_drops_the_connection(self) -> None:
        self.client.dataReceived(b"zzzzzz")
        self.assertTrue(self.wire.disconnecting)
        self.parent.received_pool_data.assert_not_called()


if __name__ == "__main__":
    unittest.main()
