# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/core/auth.py authentication classes.
# ABOUTME: Covers UserDB rule parsing and AuthRandom's returning-attacker path.

from __future__ import annotations

import shutil
import tempfile
import unittest

from cowrie.core import auth
from cowrie.core.config import CowrieConfig


class UserDBRuleTests(unittest.TestCase):
    """UserDB reloads userdb.txt on every login attempt, so one unparseable
    line breaks authentication for the whole honeypot until it is fixed."""

    def setUp(self) -> None:
        self.db = auth.UserDB.__new__(auth.UserDB)
        self.db.userdb = {}

    def test_empty_password_is_a_plain_empty_password(self) -> None:
        """A userdb.txt line ending in a bare colon ("someuser:x:") parses to
        an empty password; it must be accepted, not raise IndexError."""
        self.db.adduser(b"someuser", b"")

        self.assertTrue(self.db.checklogin(b"someuser", b""))
        self.assertFalse(self.db.checklogin(b"someuser", b"secret"))

    def test_bang_prefix_still_denies(self) -> None:
        self.db.adduser(b"root", b"!denied")

        self.assertFalse(self.db.checklogin(b"root", b"denied"))

    def test_plain_password_is_accepted(self) -> None:
        self.db.adduser(b"root", b"secret")

        self.assertTrue(self.db.checklogin(b"root", b"secret"))


class AuthRandomReturningLoginTests(unittest.TestCase):
    """Once an IP has earned access, presenting the same credentials again
    must be accepted immediately (the attempts > need branch)."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._had = CowrieConfig.has_option("honeypot", "state_path")
        self._old = (
            CowrieConfig.get("honeypot", "state_path") if self._had else None
        )
        CowrieConfig.set("honeypot", "state_path", self.tmp)
        self.addCleanup(self._restore)
        self.auth = auth.AuthRandom()

    def _restore(self) -> None:
        if self._had and self._old is not None:
            CowrieConfig.set("honeypot", "state_path", self._old)
        else:
            CowrieConfig.remove_option("honeypot", "state_path")

    def _earned(self, user: bytes, passwd: bytes, src_ip: str) -> None:
        """Seed the state left behind after this IP has already succeeded."""
        self.auth.uservar[src_ip] = {
            "max": 2,
            "try": 2,
            "tried": [],
            "user": user.decode("utf-8", errors="replace"),
            "pw": passwd.decode("utf-8", errors="replace"),
        }

    def test_returning_attacker_reauthenticates(self) -> None:
        self._earned(b"root", b"secret", "1.2.3.4")
        self.assertTrue(self.auth.checklogin(b"root", b"secret", "1.2.3.4"))

    def test_returning_attacker_with_different_user_is_not_authed(self) -> None:
        self._earned(b"root", b"secret", "1.2.3.4")
        self.assertFalse(self.auth.checklogin(b"admin", b"secret", "1.2.3.4"))


if __name__ == "__main__":
    unittest.main()
