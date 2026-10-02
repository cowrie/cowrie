# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The telnet proxy reads the byte after the client's CR to pick the
# ABOUTME: line terminator; a client need not send one in the same packet.

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.telnet_proxy import handler as telnet_handler


def _handler() -> Any:
    h = telnet_handler.TelnetHandler.__new__(telnet_handler.TelnetHandler)
    h.currentData = b""
    h.sendData = True
    h.server = MagicMock()
    h.client = MagicMock()
    h.backendLogin = b"root"
    h.backendPassword = b"secret"
    h.usernameState = b""
    h.passwordState = b""
    h.inputingLogin = True
    h.inputingPassword = True
    h.waitingLoginEcho = False
    h.prePasswordData = False
    h.spoofAuthenticationData = False
    h._log = MagicMock()
    return h


class TerminatingCharTests(unittest.TestCase):
    """A bare trailing CR must not be indexed past the end of the packet."""

    def _username(self, data: bytes) -> Any:
        h = _handler()
        h.currentData = data
        with patch.object(telnet_handler.TelnetHandler, "sendFrontend"):
            h.processUsernameInput()
        return h

    def _password(self, data: bytes, *, valid: bool = False) -> Any:
        """Before forwarding a password the handler asks the honeypot's own
        auth whether the credentials are valid. Pin that answer: it decides
        which password is forwarded, and left to itself it reads the
        operator's etc/userdb.txt, which is not part of the repository."""
        h = _handler()
        h.currentData = data
        checker = MagicMock()
        checker.return_value.checkUserPass.return_value = valid
        with patch.object(telnet_handler, "HoneypotPasswordChecker", checker):
            h.processPasswordInput()
        return h

    def test_username_with_crlf(self) -> None:
        h = self._username(b"admin\r\n")

        self.assertEqual(h.currentData, b"root\r\n")
        self.assertFalse(h.inputingLogin)

    def test_username_with_cr_nul(self) -> None:
        h = self._username(b"admin\r\x00")

        self.assertEqual(h.currentData, b"root\r\x00")

    def test_username_with_bare_trailing_cr(self) -> None:
        """The CR and its companion can land in separate reads, and some
        clients only ever send a lone CR for Enter."""
        h = self._username(b"admin\r")

        self.assertEqual(h.currentData, b"root\r")
        self.assertFalse(h.inputingLogin)

    def test_password_with_crlf(self) -> None:
        h = self._password(b"hunter2\r\n")

        self.assertEqual(h.currentData, b"secretfake\r\n")
        self.assertFalse(h.inputingPassword)

    def test_password_with_bare_trailing_cr(self) -> None:
        h = self._password(b"hunter2\r")

        self.assertEqual(h.currentData, b"secretfake\r")
        self.assertFalse(h.inputingPassword)

    def test_valid_password_forwards_the_backend_password(self) -> None:
        """Credentials the honeypot accepts send the backend its real
        password; only rejected ones get the deliberately wrong one."""
        h = self._password(b"hunter2\r\n", valid=True)

        self.assertEqual(h.currentData, b"secret\r\n")
        self.assertTrue(h.authDone)


if __name__ == "__main__":
    unittest.main()
