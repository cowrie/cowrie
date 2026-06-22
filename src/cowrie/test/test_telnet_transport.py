# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for telnet transport negotiation error handling.
# ABOUTME: Covers edge cases in telnet option negotiation chaining.

from __future__ import annotations

import gc
import unittest
from unittest.mock import MagicMock, patch

from twisted.conch.telnet import ECHO, AlreadyNegotiating, ITelnetProtocol
from twisted.internet.error import ConnectionDone
from twisted.python import failure, log
from zope.interface import implementer

from cowrie.telnet.transport import CowrieTelnetTransport


class MockOptionState:
    """Mock for Twisted's _OptionState."""

    def __init__(
        self, him_result: MagicMock | None = None, us_result: MagicMock | None = None
    ) -> None:
        self.him = MagicMock()
        self.him.onResult = him_result
        self.us = MagicMock()
        self.us.onResult = us_result


class TestHandleNegotiationError(unittest.TestCase):
    """Tests for _handleNegotiationError edge cases."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.transport = CowrieTelnetTransport()
        # Mock the transport's internal state
        self.transport.transport = MagicMock()

    def test_handles_none_us_onResult(self) -> None:
        """Test that _handleNegotiationError handles None onResult for will/wont.

        When AlreadyNegotiating is raised but the negotiation completes before
        we can chain onto it, onResult will be None. This should not crash.
        """
        # Create a failure with AlreadyNegotiating
        f = failure.Failure(AlreadyNegotiating())

        # Mock getOptionState to return state with None onResult
        mock_state = MockOptionState(us_result=None)

        # This should not raise AttributeError
        # Using self.will as the func (will/wont use s.us.onResult)
        with patch.object(self.transport, "getOptionState", return_value=mock_state):
            try:
                self.transport._handleNegotiationError(f, self.transport.will, b"\x01")
            except AttributeError as e:
                self.fail(f"_handleNegotiationError raised AttributeError: {e}")

    def test_handles_none_him_onResult(self) -> None:
        """Test that _handleNegotiationError handles None onResult for do/dont.

        When AlreadyNegotiating is raised but the negotiation completes before
        we can chain onto it, onResult will be None. This should not crash.
        """
        # Create a failure with AlreadyNegotiating
        f = failure.Failure(AlreadyNegotiating())

        # Mock getOptionState to return state with None onResult
        mock_state = MockOptionState(him_result=None)

        # This should not raise AttributeError
        # Using self.do as the func (do/dont use s.him.onResult)
        with patch.object(self.transport, "getOptionState", return_value=mock_state):
            try:
                self.transport._handleNegotiationError(f, self.transport.do, b"\x01")
            except AttributeError as e:
                self.fail(f"_handleNegotiationError raised AttributeError: {e}")

    def test_chains_when_onResult_exists(self) -> None:
        """Test that callbacks are properly chained when onResult is not None."""
        f = failure.Failure(AlreadyNegotiating())

        # Create a mock Deferred for onResult
        mock_deferred = MagicMock()
        mock_deferred.addCallback = MagicMock(return_value=mock_deferred)
        mock_deferred.addErrback = MagicMock(return_value=mock_deferred)

        mock_state = MockOptionState(us_result=mock_deferred)

        with patch.object(self.transport, "getOptionState", return_value=mock_state):
            self.transport._handleNegotiationError(f, self.transport.will, b"\x01")

        # Verify callbacks were added
        mock_deferred.addCallback.assert_called_once()
        mock_deferred.addErrback.assert_called_once()


@implementer(ITelnetProtocol)
class EchoOnlyProtocol:
    """Minimal application protocol that only agrees to echo locally."""

    def enableLocal(self, option: bytes) -> bool:
        return option == ECHO

    def enableRemote(self, option: bytes) -> bool:
        return False

    def disableLocal(self, option: bytes) -> bool:
        return True

    def disableRemote(self, option: bytes) -> bool:
        return True

    def makeConnection(self, transport: object) -> None:
        pass

    def connectionMade(self) -> None:
        pass

    def dataReceived(self, data: bytes) -> None:
        pass

    def connectionLost(self, reason: failure.Failure) -> None:
        pass

    def unhandledCommand(self, command: bytes, argument: bytes) -> None:
        pass

    def unhandledSubnegotiation(self, command: bytes, data: list[bytes]) -> None:
        pass


class CollectingTransport:
    """Underlying TCP transport stub that records bytes written."""

    def __init__(self) -> None:
        self.data = b""

    def write(self, data: bytes) -> None:
        self.data += data

    def writeSequence(self, seq: list[bytes]) -> None:
        self.data += b"".join(seq)


class TestNegotiationDuringConnectionLost(unittest.TestCase):
    """Regression tests for issue #40177.

    A telnet client that initiates option negotiation but never answers it
    leaves a negotiation permanently pending. A later willChain/wontChain on
    the same option chains retries onto the pending Deferred. When the
    connection is then lost, those retries used to fire an uncollected failed
    Deferred (AlreadyNegotiating) and mutate self.options while
    Telnet.connectionLost() iterates it, crashing the session right after a
    successful login.
    """

    def setUp(self) -> None:
        self.transport = CowrieTelnetTransport()
        self.tcp = CollectingTransport()
        self.transport.protocol = EchoOnlyProtocol()  # type: ignore[assignment]
        self.transport.transport = self.tcp  # type: ignore[assignment]
        self.transport.startTime = 0.0
        self.transport.setTimeout = lambda *a: None  # type: ignore[method-assign]

    def _drive_pending_negotiation(self) -> None:
        """Reproduce the production flow against a non-answering client.

        telnet_User -> willChain(ECHO); the client never answers, so the
        negotiation stays pending. A failed login (_ebLogin) then issues
        wontChain(ECHO), and a second telnet_User issues willChain(ECHO)
        again -- both raise AlreadyNegotiating and chain onto the pending
        Deferred.
        """
        self.transport.willChain(ECHO)
        self.transport.wontChain(ECHO)
        self.transport.willChain(ECHO)

    def test_connection_lost_after_pending_negotiation_is_clean(self) -> None:
        errors: list[failure.Failure] = []

        def observer(event: dict) -> None:
            if event.get("isError"):
                f = event.get("failure")
                if f is not None:
                    errors.append(f)

        log.addObserver(observer)
        try:
            self._drive_pending_negotiation()
            # Must not raise (e.g. "dictionary changed size during iteration").
            self.transport.connectionLost(failure.Failure(ConnectionDone()))
            # Force any uncollected failed Deferreds to be logged via __del__.
            gc.collect()
        finally:
            log.removeObserver(observer)

        unhandled = [f for f in errors if f.check(AlreadyNegotiating)]
        self.assertEqual(
            unhandled,
            [],
            f"connection teardown left {len(unhandled)} unhandled "
            "AlreadyNegotiating Deferred(s)",
        )

    def test_no_negotiation_while_closing(self) -> None:
        """While closing, negotiation must not touch self.options.

        Telnet.connectionLost() iterates self.options.values(); driving a
        negotiation there (via getOptionState -> setdefault) would insert a
        new key and raise "dictionary changed size during iteration". Once
        _closing is set, the chaining helpers must be no-ops.
        """
        self.transport._closing = True

        before = dict(self.transport.options)
        self.assertIsNone(self.transport.willChain(ECHO))
        self.assertEqual(
            self.transport.options,
            before,
            "willChain mutated self.options during teardown",
        )
        self.assertEqual(self.tcp.data, b"")


if __name__ == "__main__":
    unittest.main()
