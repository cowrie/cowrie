# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that the greynoise output plugin swallows treq request
# ABOUTME: failures instead of leaving an unhandled Deferred error (issue #1711).

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from twisted.internet import defer, error
from twisted.python.failure import Failure
from twisted.web.client import ResponseNeverReceived

from cowrie.output.greynoise import Output

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

CONNECT_EVENT = {
    "eventid": "cowrie.session.connect",
    "session": "0000000000000000",
    "src_ip": "1.2.3.4",
    "protocol": "ssh",
}


class GreyNoiseRequestFailureTests(unittest.TestCase):
    """A failed GreyNoise lookup must be handled, not left unhandled."""

    def setUp(self) -> None:
        self.output = Output()
        self.output.apiKey = "test-key"
        self.output.debug = False

    def _assert_handled(self, failure: Exception) -> None:
        with patch(
            "cowrie.output.greynoise.treq.get", return_value=defer.fail(failure)
        ):
            d = self.output.scanip(CONNECT_EVENT)
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


if __name__ == "__main__":
    unittest.main()
