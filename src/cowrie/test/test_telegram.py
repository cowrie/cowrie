# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The telegram plugin sends HTML-parsed messages, so attacker text
# ABOUTME: interpolated into them has to be escaped rather than sent as markup.

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.output import telegram


def _make() -> tuple[Any, list[str]]:
    """The plugin with its config-reading start() and its HTTP call stubbed."""
    with patch.object(telegram.Output, "start", lambda self: None):
        out = telegram.Output()
    sent: list[str] = []
    out.send_message = sent.append  # type: ignore[method-assign]
    return out, sent


def _event(**extra: str) -> dict[str, str]:
    event = {
        "sensor": "testsensor",
        "src_ip": "1.2.3.4",
        "session": "s1",
    }
    event.update(extra)
    return event


class TelegramHtmlEscapingTests(unittest.TestCase):
    def test_redirect_in_command_is_escaped(self) -> None:
        """A shell redirect is an ordinary command; unescaped it produces
        malformed HTML that the Telegram API rejects, dropping the alert."""
        out, sent = _make()

        out.write(_event(eventid="cowrie.command.input", input="ls -la > /tmp/x"))

        self.assertIn("ls -la &gt; /tmp/x", sent[0])
        self.assertNotIn("> /tmp/x", sent[0])

    def test_markup_in_command_is_not_rendered(self) -> None:
        """A crafted command must not become live markup in the operator's
        chat -- Telegram's HTML mode supports <a href>."""
        out, sent = _make()

        out.write(
            _event(
                eventid="cowrie.command.input",
                input='<a href="http://evil.example">click</a>',
            )
        )

        self.assertNotIn("<a href", sent[0])
        self.assertIn("&lt;a href=", sent[0])

    def test_ampersand_in_command_is_escaped(self) -> None:
        out, sent = _make()

        out.write(_event(eventid="cowrie.command.input", input="wget a?x=1&y=2"))

        self.assertIn("wget a?x=1&amp;y=2", sent[0])

    def test_credentials_are_escaped(self) -> None:
        out, sent = _make()

        out.write(
            _event(
                eventid="cowrie.login.success",
                username="<b>root</b>",
                password="p&w<d",
            )
        )

        self.assertIn("&lt;b&gt;root&lt;/b&gt;", sent[0])
        self.assertIn("p&amp;w&lt;d", sent[0])

    def test_download_url_is_escaped(self) -> None:
        out, sent = _make()

        out.write(
            _event(
                eventid="cowrie.session.file_download",
                url="http://evil.example/x?a=1&b=<2",
            )
        )

        self.assertIn("a=1&amp;b=&lt;2", sent[0])

    def test_wrapping_tags_survive(self) -> None:
        """The plugin's own markup must still be markup."""
        out, sent = _make()

        out.write(_event(eventid="cowrie.command.input", input="ls"))

        self.assertIn("<strong>[Cowrie testsensor]</strong>", sent[0])
        self.assertIn("<pre>ls</pre>", sent[0])


def _sent_params(out: Any) -> list[tuple[str, str]]:
    """Call send_message with treq stubbed and return the query params used."""
    out.bot_token = "token"
    out.chat_id = "-1001234567890"
    with patch("cowrie.output.telegram.treq.get", return_value=MagicMock()) as get:
        out.send_message("hello")
    params: list[tuple[str, str]] = get.call_args.kwargs["params"]
    return params


class TelegramThreadIdTests(unittest.TestCase):
    def test_thread_id_is_sent_when_set(self) -> None:
        with patch.object(telegram.Output, "start", lambda self: None):
            out = telegram.Output()
        out.thread_id = "42"

        self.assertIn(("message_thread_id", "42"), _sent_params(out))

    def test_no_thread_id_by_default(self) -> None:
        """Without a topic the request must not carry message_thread_id;
        this also covers a plugin built without running start()."""
        with patch.object(telegram.Output, "start", lambda self: None):
            out = telegram.Output()

        params = dict(_sent_params(out))

        self.assertNotIn("message_thread_id", params)
        self.assertEqual(params["chat_id"], "-1001234567890")

    def test_start_reads_thread_id_from_environment(self) -> None:
        with patch.dict(os.environ, {"COWRIE_OUTPUT_TELEGRAM_THREAD_ID": "42"}):
            out = telegram.Output()

        self.assertEqual(out.thread_id, "42")

    def test_start_without_thread_id_configured(self) -> None:
        with patch.dict(os.environ):
            os.environ.pop("COWRIE_OUTPUT_TELEGRAM_THREAD_ID", None)
            out = telegram.Output()

        self.assertEqual(out.thread_id, "")


if __name__ == "__main__":
    unittest.main()
