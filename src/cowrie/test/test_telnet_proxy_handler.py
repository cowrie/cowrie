# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The telnet proxy reads the byte after the client's CR to pick the
# ABOUTME: line terminator; a client need not send one in the same packet.

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from twisted.internet.testing import StringTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.core import ttylog
from cowrie.telnet_proxy import handler as telnet_handler
from cowrie.test.eventcapture import capture_eventlog, events_of


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


class BackendDeliveryTests(unittest.TestCase):
    """Frontend data that arrives before the backend connects is held, then
    sent and logged once per packet, in order."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {"COWRIE_HONEYPOT_TTYLOG_PATH": tmp.name}):
            self.h = telnet_handler.TelnetHandler(MagicMock())
        self.h.authStarted = True
        self.backend = MagicMock()
        self.backend.transport = StringTransport()

    def _logged_input(self) -> str:
        return ttylog.ttylog_inputhash(self.h.ttylogFile)

    def test_held_data_is_sent_when_backend_connects(self) -> None:
        self.h.sendBackend(b"early")

        self.h.setClient(self.backend)

        self.assertEqual(self.backend.transport.value(), b"early")

    def test_each_packet_is_logged_once_with_its_own_bytes(self) -> None:
        self.h.sendBackend(b"one")
        self.h.setClient(self.backend)
        self.h.sendBackend(b"two")

        self.assertEqual(self.backend.transport.value(), b"onetwo")
        self.assertEqual(self._logged_input(), hashlib.sha256(b"onetwo").hexdigest())


class LoginFlowTests(unittest.TestCase):
    """The handler follows the backend's login prompts, sends the backend its
    own account, and passes everything through once the attacker is in."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.events, self.dispatched = capture_eventlog()
        self.frontend = StringTransport()
        server = MagicMock()
        server.transport = self.frontend
        server.events = self.events
        with patch.dict(os.environ, {"COWRIE_HONEYPOT_TTYLOG_PATH": tmp.name}):
            self.h = telnet_handler.TelnetHandler(server)
        self.h.spoofAuthenticationData = True
        self.h.backendLogin = b"root"
        self.h.backendPassword = b"secret"
        self.h.usernamePromptRegex = rb"(\n|^)ubuntu login: .*"
        self.h.passwordPromptRegex = rb".*Password: .*"
        self.backend = MagicMock()
        self.backend.transport = StringTransport()
        self.h.setClient(self.backend)
        self.valid = False
        checker = MagicMock()
        checker.return_value.checkUserPass.side_effect = lambda *a: self.valid
        patcher = patch.object(telnet_handler, "HoneypotPasswordChecker", checker)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _from_backend(self, data: bytes) -> bytes:
        self.frontend.clear()
        self.h.addPacket("backend", data)
        return self.frontend.value()

    def _from_frontend(self, data: bytes) -> bytes:
        self.backend.transport.clear()
        self.h.addPacket("frontend", data)
        return self.backend.transport.value()

    def _commands(self) -> list[str]:
        return [e["input"] for e in events_of(self.dispatched, "cowrie.command.input")]

    def _log_in(self, *, valid: bool) -> None:
        self.valid = valid
        self._from_backend(b"ubuntu login: ")
        self._from_frontend(b"admin\r\n")
        self._from_backend(b"root\r\nPassword: ")
        self._from_frontend(b"hunter2\r\n")

    def test_prompts_reach_the_attacker(self) -> None:
        self.assertEqual(self._from_backend(b"ubuntu login: "), b"ubuntu login: ")

    def test_username_is_replaced_and_echoed_locally(self) -> None:
        self._from_backend(b"ubuntu login: ")

        to_backend = self._from_frontend(b"admin\r\n")

        self.assertEqual(to_backend, b"root\r\n")
        self.assertEqual(self.frontend.value(), b"ubuntu login: admin\r\n")

    def test_backend_echo_of_its_own_username_is_hidden(self) -> None:
        self._from_backend(b"ubuntu login: ")
        self._from_frontend(b"admin\r\n")

        self.assertEqual(self._from_backend(b"root\r\nPassword: "), b"Password: ")

    def test_rejected_password_sends_a_wrong_one(self) -> None:
        self._from_backend(b"ubuntu login: ")
        self._from_frontend(b"admin\r\n")
        self._from_backend(b"root\r\nPassword: ")

        self.assertEqual(self._from_frontend(b"hunter2\r\n"), b"secretfake\r\n")
        self.assertFalse(self.h.authDone)

    def test_rejected_login_can_be_retried(self) -> None:
        self._log_in(valid=False)
        self._from_backend(b"\r\nLogin incorrect\r\nubuntu login: ")

        self.assertEqual(self._from_frontend(b"admin2\r\n"), b"root\r\n")

    def test_accepted_password_sends_the_real_one(self) -> None:
        self._from_backend(b"ubuntu login: ")
        self._from_frontend(b"admin\r\n")
        self._from_backend(b"root\r\nPassword: ")
        self.valid = True

        self.assertEqual(self._from_frontend(b"hunter2\r\n"), b"secret\r\n")
        self.assertTrue(self.h.authDone)

    def test_after_login_input_passes_through_and_is_logged(self) -> None:
        self._log_in(valid=True)

        self.assertEqual(self._from_frontend(b"uname\r\n"), b"uname\r\n")
        self.assertEqual(self._from_backend(b"Linux\r\n"), b"Linux\r\n")
        self.assertIn("uname", self._commands())

    def test_tty_log_starts_at_the_first_prompt(self) -> None:
        self.h.addPacket("frontend", b"\xff\xfd\x01")
        self.assertFalse(self.h.authStarted)

        self._from_backend(b"ubuntu login: ")

        self.assertTrue(self.h.authStarted)


if __name__ == "__main__":
    unittest.main()
