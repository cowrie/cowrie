# Copyright (C) 2026 Anthropic
"""
Tests for telnet NEW-ENVIRON option parsing and CVE-2026-24061 detection.

CVE-2026-24061 is a critical authentication bypass in GNU inetutils telnetd
that exploits the USER environment variable via NEW-ENVIRON telnet option.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from cowrie.telnet.userauth import (
    NEW_ENVIRON,
    NEW_ENVIRON_ESC,
    NEW_ENVIRON_INFO,
    NEW_ENVIRON_IS,
    NEW_ENVIRON_USERVAR,
    NEW_ENVIRON_VALUE,
    NEW_ENVIRON_VAR,
    HoneyPotTelnetAuthProtocol,
)
from cowrie.telnet.transport import TELNET_OPTIONS, CowrieTelnetTransport


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


if __name__ == "__main__":
    unittest.main()
