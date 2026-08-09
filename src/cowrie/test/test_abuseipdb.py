# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Retry-After tells the abuseipdb plugin how long to stop reporting
# ABOUTME: for; HTTP allows it in seconds or as a date, so both must parse.

from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import Mock

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.output.abuseipdb import Reporter


class RetryAfterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reporter = Reporter.__new__(Reporter)
        self.reporter.dispatch = Mock()

    def test_delta_seconds(self) -> None:
        self.assertEqual(self.reporter.parse_retry_after("120"), 120)

    def test_http_date(self) -> None:
        """RFC 9110 allows an HTTP-date instead of a count of seconds."""
        when = datetime.now(timezone.utc) + timedelta(minutes=30)

        retry = self.reporter.parse_retry_after(format_datetime(when, usegmt=True))

        self.assertIsNotNone(retry)
        assert retry is not None
        self.assertAlmostEqual(retry, 1800, delta=5)

    def test_http_date_in_the_past(self) -> None:
        """Never a negative wait, which callLater would fire immediately on."""
        when = datetime.now(timezone.utc) - timedelta(minutes=30)

        self.assertEqual(
            self.reporter.parse_retry_after(format_datetime(when, usegmt=True)), 0
        )

    def test_unparseable_value(self) -> None:
        self.assertIsNone(self.reporter.parse_retry_after("soon please"))


if __name__ == "__main__":
    unittest.main()
