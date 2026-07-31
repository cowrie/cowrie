# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for cowrie/commands/nc.py.

The connection tests patch nc's reactor and the DNS resolver, so no real
network traffic is generated and every assertion runs synchronously.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from unittest import mock

if TYPE_CHECKING:
    from collections.abc import Callable

from twisted.internet import error
from twisted.internet.defer import Deferred, fail, succeed
from twisted.names import dns
from twisted.names import error as names_error
from twisted.python.failure import Failure

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.commands.nc import Command_nc, NcClientFactory, nc_rate_limiter

PROMPT = b"root@unitTest:~# "


def _fake_lookup(
    records: dict[str, list[dns.RRHeader]],
) -> Callable[[Any], Deferred]:
    """A lookupAddress double serving canned answers."""

    def lookup(name: Any) -> Deferred:
        if name in records:
            return succeed((records[name], [], []))
        return fail(names_error.DNSNameError(name))

    return lookup


def _a(address: str) -> dns.RRHeader:
    return dns.RRHeader(type=dns.A, payload=dns.Record_A(address))


class ShellNcCommandTests(unittest.TestCase):
    """Argument handling: these paths finish before any network I/O."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()
        # The limiter is a module-level singleton; keep tests isolated.
        nc_rate_limiter.reset()

    def test_help(self) -> None:
        self.proto.lineReceived(b"nc -h\n")
        output = self.tr.value()
        self.assertIn(b"OpenBSD netcat", output)
        self.assertIn(b"usage: nc", output)
        self.assertTrue(output.endswith(PROMPT))

    def test_no_args_shows_usage(self) -> None:
        self.proto.lineReceived(b"nc\n")
        self.assertIn(b"usage: nc", self.tr.value())

    def test_missing_port(self) -> None:
        self.proto.lineReceived(b"nc example.com\n")
        self.assertIn(b"nc: missing port number", self.tr.value())

    def test_invalid_port(self) -> None:
        self.proto.lineReceived(b"nc example.com 99999\n")
        self.assertIn(b"nc: port number invalid: 99999", self.tr.value())

    def test_listen_without_port(self) -> None:
        self.proto.lineReceived(b"nc -l\n")
        self.assertIn(b"nc: missing port number", self.tr.value())

    def test_listen_with_port_denied(self) -> None:
        self.proto.lineReceived(b"nc -l -p 4444\n")
        self.assertIn(b"nc: Permission denied", self.tr.value())

    def test_udp_denied(self) -> None:
        self.proto.lineReceived(b"nc -u 8.8.8.8 53\n")
        self.assertIn(b"nc: Permission denied", self.tr.value())

    def test_ipv6_unreachable(self) -> None:
        self.proto.lineReceived(b"nc -6 example.com 80\n")
        self.assertIn(b"nc: Network is unreachable", self.tr.value())


class NcConnectionTests(unittest.TestCase):
    """The outbound connection must go through the async reactor API — to the
    validated IP, bound to the configured source address, with a connect
    timeout and the download size limit enforced."""

    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()
        nc_rate_limiter.reset()
        patcher = mock.patch("cowrie.commands.nc.reactor")
        self.reactor = patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        # A test that failed mid-connection leaves its command on the stack;
        # pop it so the shared shell is usable for the next test.
        while len(self.proto.cmdstack) > 1:
            self.proto.cmdstack[-1].exit()

    def _connect(self, cmdline: bytes) -> SimpleNamespace:
        """Run an nc command line and capture the resulting connectTCP call."""
        self.proto.lineReceived(cmdline)
        self.assertEqual(self.reactor.connectTCP.call_count, 1)
        args, kwargs = self.reactor.connectTCP.call_args
        command = self.proto.cmdstack[-1]
        self.assertIsInstance(command, Command_nc)
        return SimpleNamespace(
            command=command, ip=args[0], port=args[1], factory=args[2], kwargs=kwargs
        )

    def _establish(self, factory: NcClientFactory) -> SimpleNamespace:
        """Build the client protocol and connect it to a mock transport."""
        protocol = factory.buildProtocol(None)
        transport = mock.Mock()
        protocol.makeConnection(transport)
        return SimpleNamespace(protocol=protocol, transport=transport)

    def test_connects_async_to_validated_ip(self) -> None:
        conn = self._connect(b"nc 8.8.8.8 4444\n")
        self.assertEqual(conn.ip, "8.8.8.8")
        self.assertEqual(conn.port, 4444)
        self.assertEqual(conn.kwargs["timeout"], Command_nc.CONNECT_TIMEOUT)
        self.assertEqual(conn.kwargs["bindAddress"], ("0.0.0.0", 0))

    def test_hostname_connects_to_pinned_ip(self) -> None:
        records = {"dl.example.com": [_a("8.8.4.4")]}
        with mock.patch(
            "cowrie.core.network.client.lookupAddress",
            side_effect=_fake_lookup(records),
        ):
            conn = self._connect(b"nc dl.example.com 4444\n")
        self.assertEqual(conn.ip, "8.8.4.4")

    def test_blocked_target_never_connects(self) -> None:
        self.proto.lineReceived(b"nc 10.1.1.1 4444\n")
        self.reactor.connectTCP.assert_not_called()
        self.assertEqual(self.tr.value(), PROMPT)

    def test_rate_limit_never_connects(self) -> None:
        for _ in range(5):
            self.assertTrue(nc_rate_limiter.check("8.8.8.8"))
        self.proto.lineReceived(b"nc -v 8.8.8.8 4444\n")
        self.reactor.connectTCP.assert_not_called()
        self.assertIn(b"Operation timed out", self.tr.value())

    def test_remote_data_written_to_terminal(self) -> None:
        conn = self._connect(b"nc 8.8.8.8 4444\n")
        link = self._establish(conn.factory)
        link.protocol.dataReceived(b"hello from remote\n")
        self.assertIn(b"hello from remote", self.tr.value())
        link.protocol.connectionLost(Failure(error.ConnectionDone()))
        self.assertTrue(self.tr.value().endswith(PROMPT))

    def test_verbose_success_message(self) -> None:
        conn = self._connect(b"nc -v 8.8.8.8 4444\n")
        self._establish(conn.factory)
        self.assertIn(
            b"Connection to 8.8.8.8 4444 port [tcp/*] succeeded!", self.tr.value()
        )

    def test_zero_io_closes_after_connect(self) -> None:
        conn = self._connect(b"nc -z 8.8.8.8 4444\n")
        link = self._establish(conn.factory)
        link.transport.loseConnection.assert_called_once()
        self.assertTrue(conn.command.exited)
        self.assertTrue(self.tr.value().endswith(PROMPT))

    def test_stdin_forwarded_to_remote(self) -> None:
        conn = self._connect(b"nc 8.8.8.8 4444\n")
        link = self._establish(conn.factory)
        # recvline delivers lines without their terminator, so none is added.
        self.proto.lineReceived(b"hello remote")
        link.transport.write.assert_called_once_with(b"hello remote")

    def test_download_limit_closes_connection(self) -> None:
        conn = self._connect(b"nc 8.8.8.8 4444\n")
        link = self._establish(conn.factory)
        with mock.patch.object(Command_nc, "limit_size", 10):
            link.protocol.dataReceived(b"12345")
            self.assertIn(b"12345", self.tr.value())
            link.protocol.dataReceived(b"67890ABCDEF")  # total 16 > 10
        link.transport.loseConnection.assert_called_once()
        self.assertTrue(conn.command.exited)
        self.assertNotIn(b"ABCDEF", self.tr.value())

    def test_connection_refused_verbose(self) -> None:
        conn = self._connect(b"nc -v 8.8.8.8 4444\n")
        conn.factory.clientConnectionFailed(
            None, Failure(error.ConnectionRefusedError())
        )
        self.assertIn(b"Connection refused", self.tr.value())
        self.assertTrue(conn.command.exited)

    def test_connection_timeout_verbose(self) -> None:
        conn = self._connect(b"nc -v 8.8.8.8 4444\n")
        conn.factory.clientConnectionFailed(None, Failure(error.TimeoutError()))
        self.assertIn(b"Operation timed out", self.tr.value())
        self.assertTrue(conn.command.exited)

    def test_connection_failed_silent_without_verbose(self) -> None:
        conn = self._connect(b"nc 8.8.8.8 4444\n")
        conn.factory.clientConnectionFailed(
            None, Failure(error.ConnectionRefusedError())
        )
        self.assertEqual(self.tr.value(), PROMPT)
        self.assertTrue(conn.command.exited)

    def test_ctrl_c_closes_connection(self) -> None:
        conn = self._connect(b"nc 8.8.8.8 4444\n")
        link = self._establish(conn.factory)
        conn.command.handle_CTRL_C()
        link.transport.loseConnection.assert_called_once()
        self.assertTrue(conn.command.exited)

    def test_ctrl_c_before_connect_closes_late_connection(self) -> None:
        conn = self._connect(b"nc 8.8.8.8 4444\n")
        conn.command.handle_CTRL_C()
        self.assertTrue(conn.command.exited)
        # The TCP connection completes after the command was interrupted:
        # it must be torn down, not left open.
        link = self._establish(conn.factory)
        link.transport.loseConnection.assert_called_once()


if __name__ == "__main__":
    unittest.main()
