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
from cowrie.test.eventcapture import capture_events


class TestSessionDuration(unittest.TestCase):
    """Session events must report duration as an integer duration_ms field."""

    def _event(
        self, dispatched: list[dict[str, object]], eventid: str
    ) -> dict[str, object]:
        for event in dispatched:
            if event.get("eventid") == eventid:
                return event
        self.fail(f"no {eventid} event was emitted")

    def _assert_closed_duration(self, dispatched: list[dict[str, object]]) -> None:
        event = self._event(dispatched, "cowrie.session.closed")
        ms = event["duration_ms"]
        assert isinstance(ms, int)
        self.assertNotIn("duration", event)
        self.assertGreaterEqual(ms, 5000)

    def test_ssh_duration_ms_is_int(self) -> None:
        t = ssh_transport.HoneyPotSSHTransport()
        t.transport = MagicMock()
        t.startTime = time.time() - 5
        dispatched = capture_events(t)

        with (
            patch.object(ssh_transport.HoneyPotSSHTransport, "setTimeout"),
            patch("twisted.conch.ssh.transport.SSHServerTransport.connectionLost"),
        ):
            t.connectionLost()

        self._assert_closed_duration(dispatched)

    def test_telnet_duration_ms_is_int(self) -> None:
        t = telnet_transport.CowrieTelnetTransport()
        t.startTime = time.time() - 5
        dispatched = capture_events(t)

        with (
            patch.object(telnet_transport.CowrieTelnetTransport, "setTimeout"),
            patch("twisted.conch.telnet.TelnetTransport.connectionLost"),
        ):
            t.connectionLost()

        self._assert_closed_duration(dispatched)

    def test_log_closed_duration_ms_is_int(self) -> None:
        ch = ssh_channel.CowrieSSHChannel()
        ch.ttylogFile = "/dev/null"
        ch.startTime = time.time() - 5
        dispatched = capture_events(ch)

        with (
            patch("cowrie.ssh.channel.ttylog.ttylog_close"),
            patch("twisted.conch.ssh.channel.SSHChannel.closed"),
        ):
            ch.closed()

        event = next(
            (e for e in dispatched if e.get("eventid") == "cowrie.log.closed"), None
        )
        self.assertIsNotNone(event, "no cowrie.log.closed event was dispatched")
        assert event is not None
        ms = event["duration_ms"]
        assert isinstance(ms, int)
        self.assertNotIn("duration", event)
        self.assertGreaterEqual(ms, 5000)


if __name__ == "__main__":
    unittest.main()
