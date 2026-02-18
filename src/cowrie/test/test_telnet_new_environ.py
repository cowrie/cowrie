# Copyright (C) 2026 Anthropic
"""
Tests for telnet NEW-ENVIRON option parsing and CVE-2026-24061 detection.

CVE-2026-24061 is a critical authentication bypass in GNU inetutils telnetd
that exploits the USER environment variable via NEW-ENVIRON telnet option.
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from cowrie.telnet.transport import TELNET_OPTIONS, CowrieTelnetTransport
from cowrie.telnet.userauth import (
    NEW_ENVIRON,
    NEW_ENVIRON_ESC,
    NEW_ENVIRON_IS,
    NEW_ENVIRON_USERVAR,
    NEW_ENVIRON_VALUE,
    NEW_ENVIRON_VAR,
    HoneyPotTelnetAuthProtocol,
)

if TYPE_CHECKING:
    from cowrie.core.credentials import UsernamePasswordIP


class TestNewEnvironParser(unittest.TestCase):
    """Tests for NEW-ENVIRON subnegotiation parsing."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        # Create protocol with mocked portal
        mock_portal = MagicMock()
        self.protocol = HoneyPotTelnetAuthProtocol(mock_portal)
        self.protocol.environ_received = {}

    def test_parse_single_var(self) -> None:
        """Test parsing a single VAR name/value pair."""
        # Format: VAR 'U' 'S' 'E' 'R' VALUE 'r' 'o' 'o' 't'
        data = bytes([NEW_ENVIRON_VAR]) + b"USER" + bytes([NEW_ENVIRON_VALUE]) + b"root"
        result = self.protocol._parse_new_environ_data(data)
        self.assertEqual(result, {"USER": "root"})

    def test_parse_multiple_vars(self) -> None:
        """Test parsing multiple environment variables."""
        # VAR USER VALUE root VAR TERM VALUE xterm
        data = (
            bytes([NEW_ENVIRON_VAR])
            + b"USER"
            + bytes([NEW_ENVIRON_VALUE])
            + b"root"
            + bytes([NEW_ENVIRON_VAR])
            + b"TERM"
            + bytes([NEW_ENVIRON_VALUE])
            + b"xterm"
        )
        result = self.protocol._parse_new_environ_data(data)
        self.assertEqual(result, {"USER": "root", "TERM": "xterm"})

    def test_parse_uservar(self) -> None:
        """Test parsing USERVAR (user-defined variable)."""
        # USERVAR MYVAR VALUE myvalue
        data = (
            bytes([NEW_ENVIRON_USERVAR])
            + b"MYVAR"
            + bytes([NEW_ENVIRON_VALUE])
            + b"myvalue"
        )
        result = self.protocol._parse_new_environ_data(data)
        self.assertEqual(result, {"MYVAR": "myvalue"})

    def test_parse_empty_value(self) -> None:
        """Test parsing variable with empty value."""
        # VAR USER VALUE (empty)
        data = bytes([NEW_ENVIRON_VAR]) + b"USER" + bytes([NEW_ENVIRON_VALUE])
        result = self.protocol._parse_new_environ_data(data)
        self.assertEqual(result, {"USER": ""})

    def test_parse_escape_sequence(self) -> None:
        """Test parsing with escape sequences for literal special bytes."""
        # VAR TEST VALUE with ESC 0x00 (literal VAR byte) in value
        data = (
            bytes([NEW_ENVIRON_VAR])
            + b"TEST"
            + bytes([NEW_ENVIRON_VALUE])
            + b"before"
            + bytes([NEW_ENVIRON_ESC, NEW_ENVIRON_VAR])  # Escaped VAR byte
            + b"after"
        )
        result = self.protocol._parse_new_environ_data(data)
        # The VALUE byte (0x00) should be literal in the value
        self.assertEqual(result["TEST"], "before\x00after")

    def test_parse_empty_data(self) -> None:
        """Test parsing empty data."""
        result = self.protocol._parse_new_environ_data(b"")
        self.assertEqual(result, {})

    def test_parse_cve_2026_24061_payload(self) -> None:
        """Test parsing the exact CVE-2026-24061 exploit payload."""
        # VAR USER VALUE -f root
        data = (
            bytes([NEW_ENVIRON_VAR])
            + b"USER"
            + bytes([NEW_ENVIRON_VALUE])
            + b"-f root"
        )
        result = self.protocol._parse_new_environ_data(data)
        self.assertEqual(result, {"USER": "-f root"})

    def test_parse_cve_2026_24061_variant_froot(self) -> None:
        """Test parsing CVE-2026-24061 variant: -froot (no space)."""
        data = (
            bytes([NEW_ENVIRON_VAR]) + b"USER" + bytes([NEW_ENVIRON_VALUE]) + b"-froot"
        )
        result = self.protocol._parse_new_environ_data(data)
        self.assertEqual(result, {"USER": "-froot"})


class TestCVE2026_24061Detection(unittest.TestCase):
    """Tests for CVE-2026-24061 exploit detection."""

    def setUp(self) -> None:
        """Set up test fixtures with mocked transport and logging."""
        mock_portal = MagicMock()
        self.protocol = HoneyPotTelnetAuthProtocol(mock_portal)
        self.protocol.environ_received = {}

        # Mock the transport
        self.protocol.transport = MagicMock()

    @patch("cowrie.telnet.userauth.log")
    def test_detect_exploit_f_root(self, mock_log: MagicMock) -> None:
        """Test detection of USER=-f root exploit."""
        # Simulate receiving IS VAR USER VALUE -f root
        data = [
            bytes([NEW_ENVIRON_IS]),
            bytes([NEW_ENVIRON_VAR]),
            *[bytes([c]) for c in b"USER"],
            bytes([NEW_ENVIRON_VALUE]),
            *[bytes([c]) for c in b"-f root"],
        ]
        self.protocol.telnet_NEW_ENVIRON(data)

        # Check that exploit was detected
        exploit_logged = False
        for call in mock_log.msg.call_args_list:
            if call[1].get("eventid") == "cowrie.telnet.exploit_attempt":
                exploit_logged = True
                self.assertEqual(call[1].get("cve"), "CVE-2026-24061")
                self.assertEqual(call[1].get("value"), "-f root")
                break
        self.assertTrue(exploit_logged, "CVE-2026-24061 exploit should be detected")

    @patch("cowrie.telnet.userauth.log")
    def test_detect_exploit_froot_no_space(self, mock_log: MagicMock) -> None:
        """Test detection of USER=-froot (no space) variant."""
        data = [
            bytes([NEW_ENVIRON_IS]),
            bytes([NEW_ENVIRON_VAR]),
            *[bytes([c]) for c in b"USER"],
            bytes([NEW_ENVIRON_VALUE]),
            *[bytes([c]) for c in b"-froot"],
        ]
        self.protocol.telnet_NEW_ENVIRON(data)

        exploit_logged = False
        for call in mock_log.msg.call_args_list:
            if call[1].get("eventid") == "cowrie.telnet.exploit_attempt":
                exploit_logged = True
                self.assertEqual(call[1].get("cve"), "CVE-2026-24061")
                break
        self.assertTrue(exploit_logged, "CVE-2026-24061 variant should be detected")

    @patch("cowrie.telnet.userauth.log")
    def test_detect_exploit_lowercase_user(self, mock_log: MagicMock) -> None:
        """Test detection with lowercase 'user' variable name."""
        data = [
            bytes([NEW_ENVIRON_IS]),
            bytes([NEW_ENVIRON_VAR]),
            *[bytes([c]) for c in b"user"],
            bytes([NEW_ENVIRON_VALUE]),
            *[bytes([c]) for c in b"-f root"],
        ]
        self.protocol.telnet_NEW_ENVIRON(data)

        exploit_logged = False
        for call in mock_log.msg.call_args_list:
            if call[1].get("eventid") == "cowrie.telnet.exploit_attempt":
                exploit_logged = True
                break
        self.assertTrue(exploit_logged, "Lowercase 'user' should also be detected")

    @patch("cowrie.telnet.userauth.log")
    def test_no_false_positive_normal_user(self, mock_log: MagicMock) -> None:
        """Test that normal USER values don't trigger exploit detection."""
        data = [
            bytes([NEW_ENVIRON_IS]),
            bytes([NEW_ENVIRON_VAR]),
            *[bytes([c]) for c in b"USER"],
            bytes([NEW_ENVIRON_VALUE]),
            *[bytes([c]) for c in b"admin"],
        ]
        self.protocol.telnet_NEW_ENVIRON(data)

        exploit_logged = False
        for call in mock_log.msg.call_args_list:
            if call[1].get("eventid") == "cowrie.telnet.exploit_attempt":
                exploit_logged = True
                break
        self.assertFalse(exploit_logged, "Normal username should not trigger exploit detection")

    @patch("cowrie.telnet.userauth.log")
    def test_logs_client_var_event(self, mock_log: MagicMock) -> None:
        """Test that environment variables are logged as cowrie.client.var."""
        data = [
            bytes([NEW_ENVIRON_IS]),
            bytes([NEW_ENVIRON_VAR]),
            *[bytes([c]) for c in b"TERM"],
            bytes([NEW_ENVIRON_VALUE]),
            *[bytes([c]) for c in b"xterm"],
        ]
        self.protocol.telnet_NEW_ENVIRON(data)

        var_logged = False
        for call in mock_log.msg.call_args_list:
            if call[1].get("eventid") == "cowrie.client.var":
                var_logged = True
                self.assertEqual(call[1].get("name"), "TERM")
                self.assertEqual(call[1].get("value"), "xterm")
                break
        self.assertTrue(var_logged, "Environment variable should be logged")

    @patch("cowrie.telnet.userauth.log")
    def test_ignores_send_command(self, mock_log: MagicMock) -> None:
        """Test that SEND command (server requesting values) is ignored."""
        # SEND command - server asking client for values, not client sending
        data = [
            bytes([1]),  # SEND = 1
            bytes([NEW_ENVIRON_VAR]),
            *[bytes([c]) for c in b"USER"],
        ]
        self.protocol.telnet_NEW_ENVIRON(data)

        # Should not log anything since SEND is ignored
        var_logged = False
        for call in mock_log.msg.call_args_list:
            if call[1].get("eventid") == "cowrie.client.var":
                var_logged = True
                break
        self.assertFalse(var_logged, "SEND command should be ignored")


class TestTelnetOptionLogging(unittest.TestCase):
    """Tests for telnet option negotiation logging."""

    def test_telnet_options_lookup(self) -> None:
        """Test that TELNET_OPTIONS contains expected values."""
        self.assertEqual(TELNET_OPTIONS[1], "ECHO")
        self.assertEqual(TELNET_OPTIONS[3], "SGA")
        self.assertEqual(TELNET_OPTIONS[31], "NAWS")
        self.assertEqual(TELNET_OPTIONS[39], "NEW-ENVIRON")

    def test_get_option_name_known(self) -> None:
        """Test _get_option_name for known options."""
        transport = CowrieTelnetTransport()
        self.assertEqual(transport._get_option_name(bytes([39])), "NEW-ENVIRON")
        self.assertEqual(transport._get_option_name(bytes([1])), "ECHO")

    def test_get_option_name_unknown(self) -> None:
        """Test _get_option_name for unknown options."""
        transport = CowrieTelnetTransport()
        self.assertEqual(transport._get_option_name(bytes([99])), "UNKNOWN-99")


class TestNewEnvironConstants(unittest.TestCase):
    """Tests for NEW-ENVIRON protocol constants."""

    def test_new_environ_option_byte(self) -> None:
        """Test NEW_ENVIRON option is correct (RFC 1572)."""
        self.assertEqual(NEW_ENVIRON, bytes([39]))

    def test_subnegotiation_commands(self) -> None:
        """Test subnegotiation command bytes."""
        self.assertEqual(NEW_ENVIRON_IS, 0)
        self.assertEqual(NEW_ENVIRON_VALUE, 1)
        self.assertEqual(NEW_ENVIRON_ESC, 2)


class TestCVE2026_24061Emulation(unittest.TestCase):
    """Tests for CVE-2026-24061 vulnerability emulation."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        mock_portal = MagicMock()
        self.protocol = HoneyPotTelnetAuthProtocol(mock_portal)
        self.protocol.environ_received = {}
        self.mock_transport = MagicMock()
        self.protocol.transport = self.mock_transport

    def test_extract_username_from_f_space_root(self) -> None:
        """Test extracting username from '-f root' format."""
        result = self.protocol._extract_cve_2026_24061_user("-f root")
        self.assertEqual(result, "root")

    def test_extract_username_from_froot(self) -> None:
        """Test extracting username from '-froot' format (no space)."""
        result = self.protocol._extract_cve_2026_24061_user("-froot")
        self.assertEqual(result, "root")

    def test_extract_username_from_f_admin(self) -> None:
        """Test extracting username from '-f admin' format."""
        result = self.protocol._extract_cve_2026_24061_user("-f admin")
        self.assertEqual(result, "admin")

    def test_extract_returns_none_for_normal_value(self) -> None:
        """Test that normal USER values return None."""
        result = self.protocol._extract_cve_2026_24061_user("root")
        self.assertIsNone(result)

    def test_extract_returns_none_for_other_flags(self) -> None:
        """Test that other flags don't trigger extraction."""
        result = self.protocol._extract_cve_2026_24061_user("-p root")
        self.assertIsNone(result)

    @patch("cowrie.telnet.userauth.CowrieConfig")
    @patch("cowrie.telnet.userauth.log")
    def test_exploit_sets_bypass_when_vulnerable(
        self, mock_log: MagicMock, mock_config: MagicMock
    ) -> None:
        """Test that exploit sets bypass flag when vulnerability emulation is enabled."""
        mock_config.getboolean.return_value = True

        data = [
            bytes([NEW_ENVIRON_IS]),
            bytes([NEW_ENVIRON_VAR]),
            *[bytes([c]) for c in b"USER"],
            bytes([NEW_ENVIRON_VALUE]),
            *[bytes([c]) for c in b"-f root"],
        ]
        self.protocol.telnet_NEW_ENVIRON(data)

        self.assertEqual(self.protocol.cve_2026_24061_user, "root")

    @patch("cowrie.telnet.userauth.CowrieConfig")
    @patch("cowrie.telnet.userauth.log")
    def test_exploit_does_not_set_bypass_when_not_vulnerable(
        self, mock_log: MagicMock, mock_config: MagicMock
    ) -> None:
        """Test that exploit does NOT set bypass flag when vulnerability emulation is disabled."""
        mock_config.getboolean.return_value = False

        data = [
            bytes([NEW_ENVIRON_IS]),
            bytes([NEW_ENVIRON_VAR]),
            *[bytes([c]) for c in b"USER"],
            bytes([NEW_ENVIRON_VALUE]),
            *[bytes([c]) for c in b"-f root"],
        ]
        self.protocol.telnet_NEW_ENVIRON(data)

        self.assertIsNone(getattr(self.protocol, "cve_2026_24061_user", None))

    @patch("cowrie.telnet.userauth.CowrieConfig")
    @patch("cowrie.telnet.userauth.log")
    def test_auth_bypass_uses_exploit_user(
        self, mock_log: MagicMock, mock_config: MagicMock
    ) -> None:
        """Test that auth bypass uses the exploit username instead of entered credentials."""
        # Set up mocks
        mock_config.getboolean.return_value = True
        mock_config.getint.return_value = 300

        # Set up transport mock
        mock_peer = MagicMock()
        mock_peer.host = "192.168.1.100"
        self.mock_transport.getPeer.return_value = mock_peer
        self.mock_transport.options = {}
        self.mock_transport.wontChain.return_value = MagicMock()

        # Simulate exploit being received
        self.protocol.cve_2026_24061_user = "root"
        self.protocol.username = b"ignored"

        # Track what credentials are used
        captured_creds: list[UsernamePasswordIP] = []

        def capture_login(
            creds: UsernamePasswordIP, *args: object, **kwargs: object
        ) -> MagicMock:
            captured_creds.append(creds)
            # Return a deferred-like mock
            d = MagicMock()
            d.addCallback = MagicMock(return_value=d)
            d.addErrback = MagicMock(return_value=d)
            return d

        self.protocol.portal.login = capture_login

        # Call telnet_Password with anything - should use exploit user
        self.protocol.telnet_Password(b"id")

        # Verify the credentials used the exploit username
        self.assertEqual(len(captured_creds), 1)
        self.assertEqual(captured_creds[0].username, b"root")  
    @patch("cowrie.telnet.userauth.CowrieConfig")
    @patch("cowrie.telnet.userauth.log")
    def test_exploit_success_is_logged(
        self, mock_log: MagicMock, mock_config: MagicMock
    ) -> None:
        """Test that successful exploit authentication is logged."""
        mock_config.getboolean.return_value = True
        mock_config.getint.return_value = 300

        mock_peer = MagicMock()
        mock_peer.host = "192.168.1.100"
        self.mock_transport.getPeer.return_value = mock_peer
        self.mock_transport.options = {}
        self.mock_transport.wontChain.return_value = MagicMock()

        self.protocol.cve_2026_24061_user = "root"
        self.protocol.username = b""  
        # Mock portal.login
        d = MagicMock()
        d.addCallback = MagicMock(return_value=d)
        d.addErrback = MagicMock(return_value=d)
        self.protocol.portal.login = MagicMock(return_value=d)  
        self.protocol.telnet_Password(b"id")

        # Check for exploit success log
        exploit_success_logged = False
        for call in mock_log.msg.call_args_list:
            if call[1].get("eventid") == "cowrie.telnet.exploit_success":
                exploit_success_logged = True
                self.assertEqual(call[1].get("cve"), "CVE-2026-24061")
                self.assertEqual(call[1].get("username"), "root")
                break
        self.assertTrue(exploit_success_logged, "Exploit success should be logged")


if __name__ == "__main__":
    unittest.main()
