# ABOUTME: Tests for telnet transport negotiation error handling.
# ABOUTME: Covers edge cases in telnet option negotiation chaining.

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from twisted.conch.telnet import AlreadyNegotiating
from twisted.python import failure

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


if __name__ == "__main__":
    unittest.main()
