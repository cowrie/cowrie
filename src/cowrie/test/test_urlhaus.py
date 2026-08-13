# SPDX-FileCopyrightText: 2026 Jari Huttunen <jari.tapani.huttunen@gmail.com>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that the urlhaus output plugin swallows treq request
# ABOUTME: failures instead of leaving an unhandled Deferred error (issue #1711).

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from twisted.internet import defer, error
from twisted.python.failure import Failure
from twisted.web.client import ResponseNeverReceived

from cowrie.output.urlhaus import Output

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

DOWNLOAD_EVENT = {
    "eventid": "cowrie.session.file_download",
    "session": "0000000000000000",
    "src_ip": "1.2.3.4",
    "protocol": "ssh",
    "url": "http://example.com/malware.exe",
}


class UrlhausRequestFailureTests(unittest.TestCase):
    """A failed URLhaus submission must be handled, not left unhandled."""

    def setUp(self) -> None:
        self.output = Output()
        self.output.api_key = "test-key"
        self.output.anonymous = "0"
        self.output.tags = ["cowrie", "honeypot"]
        self.output.submitted_urls = set()

    def _assert_handled(self, failure: Exception) -> None:
        with patch("cowrie.output.urlhaus.treq.post", return_value=defer.fail(failure)):
            d = self.output.submit(DOWNLOAD_EVENT)
        results: list = []
        d.addBoth(results.append)
        # The Deferred fired, and not with a lingering Failure.
        self.assertEqual(len(results), 1)
        self.assertNotIsInstance(results[0], Failure)

    def test_response_never_received_is_handled(self) -> None:
        # treq wraps a request timeout as ResponseNeverReceived([CancelledError]);
        # this is the exact failure reported in issue #1711.
        self._assert_handled(ResponseNeverReceived([Failure(defer.CancelledError())]))

    def test_cancelled_error_is_handled(self) -> None:
        self._assert_handled(defer.CancelledError())

    def test_dns_lookup_error_is_handled(self) -> None:
        self._assert_handled(error.DNSLookupError())


class UrlhausWriteTests(unittest.TestCase):
    """write() only submits download URLs, deduplicated."""

    def setUp(self) -> None:
        self.output = Output()
        self.output.api_key = "test-key"
        self.output.anonymous = "0"
        self.output.tags = ["cowrie", "honeypot"]
        self.output.submitted_urls = set()

    def test_ignores_non_download_events(self) -> None:
        with patch.object(self.output, "submit") as mock_submit:
            self.output.write({"eventid": "cowrie.session.connect"})
            mock_submit.assert_not_called()

    def test_submits_download_url_once(self) -> None:
        with patch.object(self.output, "submit") as mock_submit:
            self.output.write(DOWNLOAD_EVENT)
            self.output.write(DOWNLOAD_EVENT)
            mock_submit.assert_called_once_with(DOWNLOAD_EVENT)

    def test_ignores_download_without_url(self) -> None:
        with patch.object(self.output, "submit") as mock_submit:
            self.output.write({"eventid": "cowrie.session.file_download"})
            mock_submit.assert_not_called()


class UrlhausSubmitTests(unittest.TestCase):
    """submit() posts the expected JSON payload with the Auth-Key header."""

    def setUp(self) -> None:
        self.output = Output()
        self.output.api_key = "test-key"
        self.output.anonymous = "0"
        self.output.tags = ["cowrie", "honeypot"]
        self.output.submitted_urls = set()

    def test_posts_payload_and_headers(self) -> None:
        response = Mock()
        response.code = 200
        response.text.return_value = defer.succeed("{}")

        with patch("cowrie.output.urlhaus.treq.post") as treq_post:
            treq_post.return_value = defer.succeed(response)
            d = self.output.submit(DOWNLOAD_EVENT)

        results: list = []
        d.addBoth(results.append)
        self.assertEqual(len(results), 1)
        self.assertNotIsInstance(results[0], Failure)

        kwargs = treq_post.call_args.kwargs
        self.assertEqual(kwargs["url"], b"https://urlhaus.abuse.ch/api/")
        self.assertEqual(kwargs["headers"][b"Auth-Key"], [b"test-key"])
        self.assertEqual(kwargs["headers"][b"Content-Type"], [b"application/json"])
        payload = json.loads(kwargs["data"].decode("utf-8"))
        self.assertEqual(payload["anonymous"], "0")
        self.assertEqual(payload["submission"][0]["url"], DOWNLOAD_EVENT["url"])
        self.assertEqual(payload["submission"][0]["threat"], "malware_download")
        self.assertEqual(payload["submission"][0]["tags"], ["cowrie", "honeypot"])


if __name__ == "__main__":
    unittest.main()
