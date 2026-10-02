# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The slack output plugin must build its WebClient once at start()
# ABOUTME: and react to the event ids Cowrie really emits.

from __future__ import annotations

import sys
import types
import unittest
from typing import Any
from unittest.mock import Mock, patch

try:
    import slack  # noqa: F401
except ImportError:
    # The slack sdk is an optional dependency; stub it so the plugin imports.
    _slack = types.ModuleType("slack")
    _slack.WebClient = Mock  # type: ignore[attr-defined]
    sys.modules["slack"] = _slack

from cowrie.output import slack as slack_output


def _make(simplified: bool = True, verbose: bool = True) -> Any:
    """Construct the plugin without running its config-reading start()."""
    with patch.object(slack_output.Output, "start", lambda self: None):
        out = slack_output.Output()
    out.slack_channel = "#honeypot"
    out.slack_token = "token"
    out.simplified = simplified
    out.show_timestamp = False
    out.verbose = verbose
    return out


def _post(out: Any, event: dict[str, Any]) -> list[str]:
    """Run one event through write() and return the texts posted to Slack."""
    client = Mock()
    out.sc = client
    out.write(event)
    return [c.kwargs["text"] for c in client.chat_postMessage.call_args_list]


def _started(config: Mock) -> Any:
    """Construct the plugin and run start() once against the given config."""
    with patch.object(slack_output.Output, "start", lambda self: None):
        out = slack_output.Output()
    with patch.object(slack_output, "CowrieConfig", config):
        out.start()
    return out


def _config(**booleans: bool) -> Mock:
    """A config mock returning fixed strings and the given boolean options."""
    config = Mock()
    config.get.return_value = "dummy"
    config.getboolean.side_effect = lambda section, option, fallback=False: (
        booleans.get(option, fallback)
    )
    return config


class OutputSlackTests(unittest.TestCase):
    def test_webclient_built_once_and_reused_across_writes(self) -> None:
        """start() builds the WebClient; write() must reuse it, not rebuild."""
        client = Mock()
        with patch.object(slack_output, "WebClient", return_value=client) as webclient:
            out = _started(_config())
            out.write({"eventid": "cowrie.login.success"})
            out.write({"eventid": "cowrie.login.failed"})
        self.assertEqual(webclient.call_count, 1)
        self.assertEqual(client.chat_postMessage.call_count, 2)

    def _posted_message(self, **booleans: bool) -> str:
        client = Mock()
        with patch.object(slack_output, "WebClient", return_value=client):
            out = _started(_config(**booleans))
            out.write({"eventid": "cowrie.login.success", "session": "abc"})
        message: str = client.chat_postMessage.call_args.kwargs["text"]
        return message

    def test_timestamp_true_prefixes_simplified_message(self) -> None:
        """timestamp=true (the default) must include a timestamp."""
        message = self._posted_message(simplified=True, timestamp=True)
        self.assertRegex(message, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[")

    def test_timestamp_false_hides_it_in_simplified_message(self) -> None:
        message = self._posted_message(simplified=True, timestamp=False)
        self.assertTrue(message.startswith("["))

    def test_default_config_does_not_warn(self) -> None:
        """The 'timestamp=false is ignored' warning must not fire on defaults."""
        log = Mock()
        with (
            patch.object(slack_output, "WebClient"),
            patch.object(slack_output.Output, "_log", log),
        ):
            _started(_config())
        log.warn.assert_not_called()

    def test_timestamp_false_without_simplified_warns(self) -> None:
        log = Mock()
        with (
            patch.object(slack_output, "WebClient"),
            patch.object(slack_output.Output, "_log", log),
        ):
            _started(_config(timestamp=False))
        log.warn.assert_called_once()


class SlackEventIdTests(unittest.TestCase):
    def test_download_failed_uses_dotted_eventid(self) -> None:
        texts = _post(
            _make(),
            {
                "eventid": "cowrie.session.file_download.failed",
                "session": "abc123",
                "src_ip": "1.2.3.4",
                "url": "http://example.invalid/payload",
                "message": "Attempt to download file(s) failed",
                "system": "cowrie.ssh",
            },
        )
        self.assertEqual(len(texts), 1)
        self.assertIn("Download Failed", texts[0])

    def test_log_open_suppressed_when_not_verbose(self) -> None:
        texts = _post(
            _make(verbose=False),
            {
                "eventid": "cowrie.log.open",
                "session": "abc123",
                "src_ip": "1.2.3.4",
                "ttylog": "var/lib/cowrie/tty/abc",
                "message": "Opening TTY Log",
                "system": "cowrie.ssh",
            },
        )
        self.assertEqual(texts, [])

    def test_session_connect_posts(self) -> None:
        texts = _post(
            _make(),
            {
                "eventid": "cowrie.session.connect",
                "session": "abc123",
                "src_ip": "1.2.3.4",
                "src_port": 55555,
                "protocol": "ssh",
                "message": "New connection",
                "system": "cowrie.ssh",
            },
        )
        self.assertEqual(len(texts), 1)
        self.assertIn("CONNECT", texts[0])


if __name__ == "__main__":
    unittest.main()
