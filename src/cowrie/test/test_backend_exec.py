# SPDX-FileCopyrightText: 2026 Kunal Singh
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import socket
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from twisted.internet import defer, error, protocol, reactor, task
from twisted.python.failure import Failure

from backend_pool import ssh_exec, telnet_exec
from cowrie.test.proxy_compare import ProxyTestCommand
from cowrie.test.reactorpump import pump


def capture(result):
    outcomes = []
    result.addBoth(lambda value: outcomes.append(value))
    return outcomes


class ConnectionFailureTests(unittest.TestCase):
    def test_connection_refusal_reaches_returned_deferred(self):
        for module, execute in (
            (ssh_exec, ssh_exec.execute_ssh),
            (telnet_exec, telnet_exec.execute_telnet),
        ):
            with self.subTest(protocol=module.__name__):
                with patch.object(module.reactor, "connectTCP") as connect:
                    result = execute("example.invalid", 2222, "root", "password", b"id")
                outcomes = capture(result)
                reason = Failure(error.ConnectionRefusedError())
                factory = connect.call_args.args[2]
                with patch.object(telnet_exec.TelnetFactory, "_log"):
                    factory.clientConnectionFailed(None, reason)
                self.assertEqual(outcomes, [reason])

    def test_connection_loss_reaches_returned_deferred_once(self):
        for factory_type, arguments in (
            (ssh_exec.ClientCommandFactory, ("root", "password", b"id")),
            (telnet_exec.TelnetFactory, ("root", "password", ":~#", "id")),
        ):
            with self.subTest(factory=factory_type.__name__):
                result = defer.Deferred()
                outcomes = capture(result)
                factory = factory_type(*arguments, result, None)
                reason = Failure(error.ConnectionLost())
                factory.clientConnectionLost(None, reason)
                factory.clientConnectionLost(None, reason)
                self.assertEqual(outcomes, [reason])

    def test_disconnect_after_success_preserves_result(self):
        for factory_type, arguments in (
            (ssh_exec.ClientCommandFactory, ("root", "password", b"id")),
            (telnet_exec.TelnetFactory, ("root", "password", ":~#", "id")),
        ):
            with self.subTest(factory=factory_type.__name__):
                result = defer.Deferred()
                outcomes = capture(result)
                factory = factory_type(*arguments, result, None)
                result.callback(b"uid=0")
                factory.clientConnectionLost(None, Failure(error.ConnectionDone()))
                self.assertEqual(outcomes, [b"uid=0"])


class SshCompletionTests(unittest.TestCase):
    def test_channel_completion_survives_immediate_disconnect(self):
        result = defer.Deferred()
        outcomes = capture(result)
        callback = Mock()
        factory = ssh_exec.ClientCommandFactory(
            "root", "password", b"id", result, callback
        )
        transport = Mock()
        transport.loseConnection.side_effect = lambda: factory.clientConnectionLost(
            None, Failure(error.ConnectionDone())
        )
        channel = ssh_exec.CommandChannel(
            b"id", result, callback, conn=SimpleNamespace(transport=transport)
        )
        channel.dataReceived(b"uid=")
        channel.extReceived(1, b"0")
        channel.closeReceived()
        channel.closeReceived()
        self.assertEqual(outcomes, [b"uid=0"])
        callback.assert_called_once_with(b"uid=0")

    def test_late_channel_close_does_not_report_success(self):
        result = defer.Deferred()
        outcomes = capture(result)
        callback = Mock()
        channel = ssh_exec.CommandChannel(
            b"id", result, callback, conn=SimpleNamespace(transport=Mock())
        )
        reason = Failure(error.ConnectionLost())
        result.errback(reason)
        channel.closeReceived()
        self.assertEqual(outcomes, [reason])
        callback.assert_not_called()


class TelnetCompletionTests(unittest.TestCase):
    def make_client(self):
        result = defer.Deferred()
        callback = Mock()
        factory = telnet_exec.TelnetFactory(
            "root", "password", ":~#", "id", result, callback
        )
        client = telnet_exec.TelnetClient()
        client.factory = factory
        client.transport = Mock()
        client.command = b"id"
        return client, result, callback

    def test_disconnect_cancels_completion_timer_and_reports_failure(self):
        client, result, callback = self.make_client()
        outcomes = capture(result)
        clock = task.Clock()
        with patch.object(telnet_exec, "reactor", clock):
            client.lineReceived(b"partial output")
        reason = Failure(error.ConnectionLost())
        client.connectionLost(reason)
        client.factory.clientConnectionLost(None, reason)
        clock.advance(1)
        self.assertEqual(outcomes, [reason])
        self.assertEqual(clock.getDelayedCalls(), [])
        callback.assert_not_called()

    def test_normal_completion_survives_immediate_disconnect(self):
        client, result, callback = self.make_client()
        outcomes = capture(result)
        client.response = b"uid=0\r\n"
        client.transport.loseConnection.side_effect = lambda: client.connectionLost(
            Failure(error.ConnectionDone())
        )
        client.close()
        client.close()
        self.assertEqual(outcomes, [b"uid=0\r\n"])
        callback.assert_called_once_with(b"uid=0\r\n")

    def test_disconnect_before_output_reports_failure(self):
        client, result, callback = self.make_client()
        outcomes = capture(result)
        reason = Failure(error.ConnectionLost())
        client.connectionLost(reason)
        self.assertEqual(outcomes, [reason])
        callback.assert_not_called()


class ProxyComparisonTests(unittest.TestCase):
    def make_command(self):
        command = ProxyTestCommand(
            "ssh", "example.invalid", 22, 2222, "root", "pw", "root", "pw"
        )
        requests = []

        def execute(*args):
            result = defer.Deferred()
            result.addCallback(args[-1])
            requests.append(result)
            return result

        command.execute = execute
        return command, requests

    def test_either_connection_failure_finishes_comparison(self):
        for failed_index in (0, 1):
            with self.subTest(failed_index=failed_index):
                command, requests = self.make_command()
                outcomes = capture(command.deferred)
                command.execute_both(b"id")
                reason = Failure(error.ConnectionRefusedError())
                requests[failed_index].errback(reason)
                self.assertEqual(outcomes, [reason])
                requests[1 - failed_index].callback(b"late output")
                self.assertEqual(outcomes, [reason])

    def test_second_failure_does_not_fire_comparison_twice(self):
        command, requests = self.make_command()
        outcomes = capture(command.deferred)
        command.execute_both(b"id")
        reason = Failure(error.ConnectionLost())
        requests[0].errback(reason)
        requests[1].errback(Failure(error.ConnectionLost()))
        self.assertEqual(outcomes, [reason])

    def test_empty_matching_output_completes_in_either_order(self):
        for first_index in (0, 1):
            with self.subTest(first_index=first_index):
                command, requests = self.make_command()
                outcomes = capture(command.deferred)
                command.execute_both(b"true")
                requests[first_index].callback(b"")
                self.assertEqual(outcomes, [])
                requests[1 - first_index].callback(b"")
                self.assertEqual(outcomes, [True])

    def test_mismatched_output_reports_error(self):
        command, requests = self.make_command()
        outcomes = capture(command.deferred)
        command.execute_both(b"id")
        requests[0].callback(b"backend")
        requests[1].callback(b"proxy")
        self.assertEqual(len(outcomes), 1)
        self.assertTrue(outcomes[0].check(ValueError))

    def test_execute_one_propagates_connection_failure(self):
        command, requests = self.make_command()
        result = defer.Deferred()
        outcomes = capture(result)
        command.execute_one(False, b"id", result)
        reason = Failure(error.ConnectionRefusedError())
        requests[0].errback(reason)
        self.assertEqual(outcomes, [reason])

    def test_execute_one_preserves_success(self):
        command, requests = self.make_command()
        result = defer.Deferred()
        outcomes = capture(result)
        command.execute_one(False, b"id", result)
        requests[0].callback(b"uid=0")
        self.assertEqual(outcomes, [b"uid=0"])


class BackendNetworkTests(unittest.TestCase):
    def test_real_connection_refusal_reaches_both_callers(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        for execute in (ssh_exec.execute_ssh, telnet_exec.execute_telnet):
            with self.subTest(execute=execute.__name__):
                with patch.object(telnet_exec.TelnetFactory, "_log"):
                    result = execute("127.0.0.1", port, "root", "password", b"id")
                    outcomes = capture(result)
                    self.assertTrue(pump(lambda outcomes=outcomes: outcomes))
                self.assertEqual(len(outcomes), 1)
                self.assertTrue(outcomes[0].check(error.ConnectionRefusedError))

    def test_real_disconnect_before_authentication_reaches_both_callers(self):
        class DropConnection(protocol.Protocol):
            def connectionMade(self):
                self.transport.abortConnection()

        listener = reactor.listenTCP(
            0, protocol.Factory.forProtocol(DropConnection), interface="127.0.0.1"
        )
        try:
            for execute in (ssh_exec.execute_ssh, telnet_exec.execute_telnet):
                with self.subTest(execute=execute.__name__):
                    result = execute(
                        "127.0.0.1", listener.getHost().port, "root", "password", b"id"
                    )
                    outcomes = capture(result)
                    self.assertTrue(pump(lambda outcomes=outcomes: outcomes))
                    self.assertEqual(len(outcomes), 1)
                    self.assertIsInstance(outcomes[0], Failure)
                    self.assertTrue(
                        outcomes[0].check(error.ConnectionLost, error.ConnectionDone)
                    )
        finally:
            stopped = listener.stopListening()
            if stopped is not None:
                self.assertTrue(pump(lambda: stopped.called))
