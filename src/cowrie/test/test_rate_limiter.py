# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/core/rate_limiter.py — the outbound per-host limiter.
# ABOUTME: covers case-insensitive host keying so case variation can't bypass it.

from __future__ import annotations

import unittest

from cowrie.core.rate_limiter import RateLimiter


class RateLimiterCaseInsensitiveTests(unittest.TestCase):
    """DNS hostnames are case-insensitive, so case variants of one host must
    share a single bucket (otherwise the per-host limit is trivially bypassed)."""

    def test_case_variants_share_one_bucket(self) -> None:
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        self.assertTrue(limiter.check("example.com"))
        self.assertTrue(limiter.check("EXAMPLE.com"))
        # Third request for the same host (any case) exceeds max_requests=2.
        self.assertFalse(limiter.check("Example.Com"))

    def test_distinct_hosts_keep_separate_buckets(self) -> None:
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        self.assertTrue(limiter.check("a.example.com"))
        self.assertTrue(limiter.check("b.example.com"))


if __name__ == "__main__":
    unittest.main()
