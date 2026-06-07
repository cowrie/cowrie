# SPDX-FileCopyrightText: 2024 Aryan Shastri <aryanshastri1306@gmail.com>
# SPDX-FileCopyrightText: 2024-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from cowrie.output.signal import Output

_TEST_CREDENTIAL = "test-credential-value"


class SignalOutputTests(unittest.TestCase):
    """Tests for Signal messenger output plugin."""

    def setUp(self) -> None:
        self.output = Output()
        # Override with test values after start() reads from bundled cfg.dist defaults
        self.output.api_url = "https://localhost:8080"
        self.output.sender = "+1234567890"
        self.output.recipients = ["+0987654321"]

    def _base_event(self, eventid: str) -> dict:
        return {
            "eventid": eventid,
            "sensor": "test-sensor",
            "src_ip": "192.0.2.1",  # RFC 5737 TEST-NET, safe for tests
            "session": "abc123",
        }

    @patch("treq.post")
    def test_login_success_sends_notification(self, mock_post: MagicMock) -> None:
        event = {
            **self._base_event("cowrie.login.success"),
            "username": "root",
            "password": _TEST_CREDENTIAL,
        }
        self.output.write(event)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "https://localhost:8080/v2/send")
        self.assertIn(b'"message"', kwargs["data"])
        self.assertIn(b'"number"', kwargs["data"])
        self.assertIn(b'"recipients"', kwargs["data"])
        self.assertIn(b"root", kwargs["data"])
        self.assertIn(_TEST_CREDENTIAL.encode(), kwargs["data"])

    @patch("treq.post")
    def test_command_input_sends_notification(self, mock_post: MagicMock) -> None:
        event = {
            **self._base_event("cowrie.command.input"),
            "input": "cat /etc/passwd",
        }
        self.output.write(event)

        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertIn(b"cat /etc/passwd", kwargs["data"])

    @patch("treq.post")
    def test_command_failed_sends_notification(self, mock_post: MagicMock) -> None:
        event = {
            **self._base_event("cowrie.command.failed"),
            "input": "rm -rf /",
        }
        self.output.write(event)

        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertIn(b"rm -rf /", kwargs["data"])

    @patch("treq.post")
    def test_file_download_sends_notification(self, mock_post: MagicMock) -> None:
        event = {
            **self._base_event("cowrie.session.file_download"),
            "url": "https://evil.example.com/malware.sh",
        }
        self.output.write(event)

        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertIn(b"evil.example.com", kwargs["data"])

    @patch("treq.post")
    def test_file_download_without_url_sends_notification(
        self, mock_post: MagicMock
    ) -> None:
        event = self._base_event("cowrie.session.file_download")
        self.output.write(event)

        mock_post.assert_called_once()

    @patch("treq.post")
    def test_ignored_events_do_not_send(self, mock_post: MagicMock) -> None:
        ignored = [
            "cowrie.session.connect",
            "cowrie.login.failed",
            "cowrie.session.closed",
            "cowrie.client.version",
        ]
        for eventid in ignored:
            mock_post.reset_mock()
            self.output.write(self._base_event(eventid))
            mock_post.assert_not_called()

    @patch("treq.post")
    def test_post_uses_correct_content_type(self, mock_post: MagicMock) -> None:
        event = {
            **self._base_event("cowrie.login.success"),
            "username": "admin",
            "password": _TEST_CREDENTIAL,
        }
        self.output.write(event)

        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"], {b"Content-Type": [b"application/json"]})

    @patch("treq.post")
    def test_payload_contains_sender_and_recipients(self, mock_post: MagicMock) -> None:
        self.output.sender = "+1111111111"
        self.output.recipients = ["+2222222222", "+3333333333"]
        event = {
            **self._base_event("cowrie.login.success"),
            "username": "u",
            "password": _TEST_CREDENTIAL,
        }
        self.output.write(event)

        _, kwargs = mock_post.call_args
        payload = json.loads(kwargs["data"].decode("utf-8"))
        self.assertEqual(payload["number"], "+1111111111")
        self.assertIn("+2222222222", payload["recipients"])
        self.assertIn("+3333333333", payload["recipients"])

    @patch("treq.post")
    def test_send_attaches_errback(self, mock_post: MagicMock) -> None:
        mock_deferred = MagicMock()
        mock_post.return_value = mock_deferred
        event = {
            **self._base_event("cowrie.login.success"),
            "username": "root",
            "password": _TEST_CREDENTIAL,
        }
        self.output.write(event)
        mock_deferred.addErrback.assert_called_once()

    @patch("treq.post")
    def test_log_keys_stripped_before_send(self, mock_post: MagicMock) -> None:
        event = {
            **self._base_event("cowrie.login.success"),
            "username": "root",
            "password": _TEST_CREDENTIAL,
            "log_legacy": "should be removed",
            "log_text": "also removed",
        }
        self.output.write(event)

        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        data = kwargs["data"].decode("utf-8")
        self.assertNotIn("log_legacy", data)
        self.assertNotIn("log_text", data)


if __name__ == "__main__":
    unittest.main()
