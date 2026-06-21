# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the SSH password credential checker.
# ABOUTME: Covers the fallback when auth_class is misconfigured.

from __future__ import annotations

import unittest
from unittest.mock import patch

from cowrie.core import auth
from cowrie.core.checkers import HoneypotPasswordChecker
from cowrie.core.config import CowrieConfig


class TestHoneypotPasswordChecker(unittest.TestCase):
    """checkUserPass must not crash when auth_class is unknown."""

    def setUp(self) -> None:
        self._had_option = CowrieConfig.has_option("honeypot", "auth_class")
        self._old = (
            CowrieConfig.get("honeypot", "auth_class") if self._had_option else None
        )

    def tearDown(self) -> None:
        if self._had_option:
            CowrieConfig.set("honeypot", "auth_class", self._old)
        else:
            CowrieConfig.remove_option("honeypot", "auth_class")

    def test_unknown_auth_class_falls_back_to_userdb(self) -> None:
        CowrieConfig.set("honeypot", "auth_class", "NoSuchAuthClass")
        checker = HoneypotPasswordChecker()
        with patch.object(auth, "UserDB") as mock_userdb:
            mock_userdb.return_value.checklogin.return_value = False
            result = checker.checkUserPass(b"root", b"toor", "1.2.3.4")
        self.assertFalse(result)
        mock_userdb.assert_called_once()


if __name__ == "__main__":
    unittest.main()
