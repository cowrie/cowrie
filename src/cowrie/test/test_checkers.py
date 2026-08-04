# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the SSH password credential checker.
# ABOUTME: Covers the fallback when auth_class is misconfigured.

from __future__ import annotations

import unittest
from typing import Any
from unittest.mock import patch

from cowrie.core import auth
from cowrie.core.checkers import HoneypotNoneChecker, HoneypotPasswordChecker
from cowrie.core.config import CowrieConfig
from cowrie.core.credentials import Username, UsernamePasswordIP
from cowrie.test.eventcapture import capture_eventlog


def login_events(dispatched: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        e
        for e in dispatched
        if e.get("eventid") in ("cowrie.login.success", "cowrie.login.failed")
    ]


class TestHoneypotPasswordChecker(unittest.TestCase):
    """checkUserPass must not crash when auth_class is unknown."""

    def setUp(self) -> None:
        self._had_option = CowrieConfig.has_option("honeypot", "auth_class")
        self._old = (
            CowrieConfig.get("honeypot", "auth_class") if self._had_option else None
        )
        self.events, self.dispatched = capture_eventlog(protocol="ssh")

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
            result = checker.checkUserPass(b"root", b"toor", "1.2.3.4", self.events)
        self.assertFalse(result)
        mock_userdb.assert_called_once()

    def test_credentials_with_control_bytes_are_escaped(self) -> None:
        """Attacker-controlled username/password must not log raw control bytes."""
        checker = HoneypotPasswordChecker()
        with patch.object(auth, "UserDB") as mock_userdb:
            mock_userdb.return_value.checklogin.return_value = False
            checker.checkUserPass(b"ro\x00ot", b"pa\r\nss", "1.2.3.4", self.events)

        events = login_events(self.dispatched)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["eventid"], "cowrie.login.failed")
        self.assertEqual(events[0]["username"], "ro\\x00ot")
        self.assertEqual(events[0]["password"], "pa\\x0d\\x0ass")

    def test_login_event_carries_session_identity(self) -> None:
        """Login events must arrive attributed through the credentials'
        EventLog, not reconstructed from the log context."""
        checker = HoneypotPasswordChecker()
        creds = UsernamePasswordIP(b"root", b"toor", "1.2.3.4", events=self.events)
        with patch.object(auth, "UserDB") as mock_userdb:
            mock_userdb.return_value.checklogin.return_value = True
            checker.requestAvatarId(creds)

        events = login_events(self.dispatched)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["eventid"], "cowrie.login.success")
        self.assertEqual(events[0]["session"], "test0000")


class TestHoneypotPublicKeyChecker(unittest.TestCase):
    def test_pubkey_attempt_dispatches_fingerprint_and_login_failed(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from twisted.conch.ssh import keys
        from twisted.cred.credentials import SSHPrivateKey

        from cowrie.core.checkers import HoneypotPublicKeyChecker

        events, dispatched = capture_eventlog(protocol="ssh")
        blob = keys.Key(ed25519.Ed25519PrivateKey.generate()).public().blob()
        creds = SSHPrivateKey(b"root", b"ssh-ed25519", blob, None, None)
        creds.events = events  # type: ignore[attr-defined]

        HoneypotPublicKeyChecker().requestAvatarId(creds)

        fingerprints = [
            e for e in dispatched if e["eventid"] == "cowrie.client.fingerprint"
        ]
        self.assertEqual(len(fingerprints), 1)
        self.assertEqual(fingerprints[0]["username"], "root")
        self.assertEqual(fingerprints[0]["session"], "test0000")
        failed = login_events(dispatched)
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["eventid"], "cowrie.login.failed")


class TestEventsAttachingPortal(unittest.TestCase):
    def test_login_attaches_events_to_credentials(self) -> None:
        from types import SimpleNamespace

        from cowrie.ssh.userauth import EventsAttachingPortal

        seen: list[Any] = []
        inner = SimpleNamespace(
            login=lambda creds, mind, *interfaces: seen.append(creds)
        )
        events, _ = capture_eventlog(protocol="ssh")
        creds = SimpleNamespace()
        EventsAttachingPortal(inner, events).login(creds, None, object)
        self.assertEqual(seen, [creds])
        self.assertIs(creds.events, events)


class TestHoneypotNoneChecker(unittest.TestCase):
    def test_none_auth_dispatches_login_success(self) -> None:
        events, dispatched = capture_eventlog(protocol="ssh")
        checker = HoneypotNoneChecker()
        checker.requestAvatarId(Username(b"root", events=events))

        captured = login_events(dispatched)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["eventid"], "cowrie.login.success")
        self.assertEqual(captured[0]["session"], "test0000")


if __name__ == "__main__":
    unittest.main()
