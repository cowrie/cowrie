# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the SSH password credential checker.
# ABOUTME: Covers the fallback when auth_class is misconfigured.

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING
from unittest.mock import patch

from twisted.python import log

from cowrie.core import auth
from cowrie.core.checkers import HoneypotPasswordChecker
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from collections.abc import Callable


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

    def _capture_login(self, run: Callable[[], object]) -> list[dict]:
        events: list[dict] = []
        log.addObserver(events.append)
        try:
            run()
        finally:
            log.removeObserver(events.append)
        return [
            e
            for e in events
            if e.get("eventid") in ("cowrie.login.success", "cowrie.login.failed")
        ]

    def test_credentials_with_control_bytes_are_escaped(self) -> None:
        """Attacker-controlled username/password must not log raw control bytes."""
        checker = HoneypotPasswordChecker()
        with patch.object(auth, "UserDB") as mock_userdb:
            mock_userdb.return_value.checklogin.return_value = False
            events = self._capture_login(
                lambda: checker.checkUserPass(b"ro\x00ot", b"pa\r\nss", "1.2.3.4")
            )

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["username"], "ro\\x00ot")
        self.assertEqual(events[0]["password"], "pa\\x0d\\x0ass")


if __name__ == "__main__":
    unittest.main()
