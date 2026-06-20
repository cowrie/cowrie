# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that cowrie.session.closed reports duration_ms as an integer.
# ABOUTME: Guards against type drift between SSH and telnet session events.

from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock, patch

from cowrie.ssh import channel as ssh_channel
from cowrie.ssh import transport as ssh_transport
from cowrie.telnet import transport as telnet_transport


class TestSessionDuration(unittest.TestCase):
    """Session events must report duration as an integer duration_ms field."""

    def _event(self, mock_msg: MagicMock, eventid: str) -> dict[str, object]:
        for call in mock_msg.call_args_list:
            if call.kwargs.get("eventid") == eventid:
                return dict(call.kwargs)
        self.fail(f"no {eventid} event was emitted")

    def _closed_event(self, mock_msg: MagicMock) -> dict[str, object]:
        return self._event(mock_msg, "cowrie.session.closed")

    def test_ssh_duration_ms_is_int(self) -> None:
        t = ssh_transport.HoneyPotSSHTransport()
        t.transport = MagicMock()
        t.startTime = time.time() - 5

        with (
            patch("cowrie.ssh.transport.log.msg") as mock_msg,
            patch.object(ssh_transport.HoneyPotSSHTransport, "setTimeout"),
            patch("twisted.conch.ssh.transport.SSHServerTransport.connectionLost"),
        ):
            t.connectionLost()

        event = self._closed_event(mock_msg)
        ms = event["duration_ms"]
        assert isinstance(ms, int)
        self.assertNotIn("duration", event)
        self.assertGreaterEqual(ms, 5000)

    def test_telnet_duration_ms_is_int(self) -> None:
        t = telnet_transport.CowrieTelnetTransport()
        t.startTime = time.time() - 5

        with (
            patch("cowrie.telnet.transport.log.msg") as mock_msg,
            patch.object(telnet_transport.CowrieTelnetTransport, "setTimeout"),
            patch("twisted.conch.telnet.TelnetTransport.connectionLost"),
        ):
            t.connectionLost()

        event = self._closed_event(mock_msg)
        ms = event["duration_ms"]
        assert isinstance(ms, int)
        self.assertNotIn("duration", event)
        self.assertGreaterEqual(ms, 5000)

    def test_log_closed_duration_ms_is_int(self) -> None:
        ch = ssh_channel.CowrieSSHChannel()
        ch.ttylogFile = "/dev/null"
        ch.startTime = time.time() - 5

        with (
            patch("cowrie.ssh.channel.log.msg") as mock_msg,
            patch("cowrie.ssh.channel.ttylog.ttylog_close"),
            patch("twisted.conch.ssh.channel.SSHChannel.closed"),
        ):
            ch.closed()

        event = self._event(mock_msg, "cowrie.log.closed")
        ms = event["duration_ms"]
        assert isinstance(ms, int)
        self.assertNotIn("duration", event)
        self.assertGreaterEqual(ms, 5000)


if __name__ == "__main__":
    unittest.main()
