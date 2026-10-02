# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Output plugins that make HTTP requests must handle a failed request
# ABOUTME: instead of leaving an unhandled Deferred error (issue #1711 class).

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any
from unittest.mock import Mock, patch

from twisted.internet import defer
from twisted.python.failure import Failure
from twisted.web.client import ResponseNeverReceived

from cowrie.output import axiom, datadog, graylog, telegram

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


def _network_failure() -> Failure:
    # What treq raises when a request times out (issue #1711).
    return Failure(ResponseNeverReceived([Failure(defer.CancelledError())]))


def _make(module: Any) -> Any:
    """Construct a plugin without running its config-reading start()."""
    with patch.object(module.Output, "start", lambda self: None):
        return module.Output()


def _assert_handled(test: unittest.TestCase, deferred: defer.Deferred) -> None:
    seen: list = []
    deferred.addBoth(seen.append)
    test.assertEqual(len(seen), 1)
    test.assertNotIsInstance(seen[0], Failure)


class OutputNetworkErrorTests(unittest.TestCase):
    """A failed HTTP request must be handled, not left as an unhandled Deferred."""

    def test_axiom_request_failure_is_handled(self) -> None:
        out = _make(axiom)
        out.url = b"https://example.invalid"
        out.headers = {}
        d_fail: defer.Deferred = defer.fail(_network_failure())
        with patch("cowrie.output.axiom.treq.post", return_value=d_fail):
            written = out.write({"timestamp": "2026-01-01T00:00:00Z", "eventid": "t"})
        _assert_handled(self, written)

    def test_datadog_request_failure_is_handled(self) -> None:
        out = _make(datadog)
        out.agent = Mock()
        d_fail: defer.Deferred = defer.fail(_network_failure())
        out.agent.request.return_value = d_fail
        out.url = b"https://example.invalid"
        out.ddsource = "cowrie"
        out.ddtags = "env:test"
        out.service = "honeypot"
        out.hostname = "unitTest"
        out.api_key = b""
        out.write({"eventid": "t", "session": "s"})
        _assert_handled(self, d_fail)

    def test_graylog_request_failure_is_handled(self) -> None:
        out = _make(graylog)
        out.agent = Mock()
        d_fail: defer.Deferred = defer.fail(_network_failure())
        out.agent.request.return_value = d_fail
        out.url = b"https://example.invalid"
        out.write({"sensor": "unitTest", "eventid": "t"})
        _assert_handled(self, d_fail)

    def test_telegram_request_failure_is_handled(self) -> None:
        out = _make(telegram)
        out.bot_token = "token"
        out.chat_id = "123"
        d_fail: defer.Deferred = defer.fail(_network_failure())
        with patch("cowrie.output.telegram.treq.get", return_value=d_fail):
            out.send_message("hello")
        _assert_handled(self, d_fail)


if __name__ == "__main__":
    unittest.main()
