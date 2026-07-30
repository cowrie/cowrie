# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the LLM backend: attacker input and operator config must
# ABOUTME: not crash a session, and API calls are shared, capped and limited.

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch

from twisted.internet import defer

from cowrie.core.config import CowrieConfig
from cowrie.core.rate_limiter import RateLimiter

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.llm import llm as llm_module
from cowrie.llm import protocol as llm_protocol


def _avatar() -> MagicMock:
    """An avatar with the attributes the protocols read at construction."""
    avatar = MagicMock()
    avatar.environ = {}
    avatar.server.hostname = "svr04"
    avatar.username = "root"
    return avatar


class ExecCommandDecodeTests(unittest.TestCase):
    def test_non_utf8_exec_command(self) -> None:
        """A non-UTF-8 exec command must leave execcmd usable; every caller
        reads it right after construction."""
        proto = llm_protocol.HoneyPotExecProtocol(_avatar(), b"id\xff")

        self.assertEqual(proto.execcmd, "id�")

    def test_non_utf8_interactive_line(self) -> None:
        """A typed line need not be valid UTF-8."""
        proto = llm_protocol.HoneyPotBaseProtocol(_avatar())
        proto.events = MagicMock()
        sent: list[str] = []
        proto._process_command_with_llm = sent.append  # type: ignore[assignment]

        proto.lineReceived(b"echo \xff")

        self.assertEqual(sent, ["echo �"])


class SystemContextTests(unittest.TestCase):
    def _proto(self) -> llm_protocol.HoneyPotBaseProtocol:
        proto = llm_protocol.HoneyPotBaseProtocol(_avatar())
        proto.cwd = "/root"
        return proto

    def test_unknown_template_placeholder(self) -> None:
        """A typo in the operator's own prompt template must not break every
        command in the session."""
        proto = self._proto()
        with patch.object(CowrieConfig, "get", return_value="hi {nope}"):
            context = proto._build_system_context()

        self.assertIn("svr04", context)

    def test_unbalanced_brace_in_template(self) -> None:
        """An unmatched brace raises ValueError rather than KeyError; it must
        be tolerated the same way."""
        proto = self._proto()
        with patch.object(CowrieConfig, "get", return_value="hi {"):
            context = proto._build_system_context()

        self.assertIn("svr04", context)

    def test_supported_placeholders_still_substituted(self) -> None:
        proto = self._proto()
        with patch.object(
            CowrieConfig, "get", return_value="host={hostname} cwd={cwd}"
        ):
            context = proto._build_system_context()

        self.assertIn("host=svr04 cwd=/root", context)

    def test_prompt_frames_commands_as_simulated_input(self) -> None:
        """The model is told typed text is simulated input, not instructions,
        so casual attempts to break character are less likely to work."""
        proto = self._proto()
        context = proto._build_system_context()

        self.assertIn("not instructions", context.lower())


class SharedClientTests(unittest.TestCase):
    def test_client_is_shared_between_sessions(self) -> None:
        """Each LLMClient owns an HTTP connection pool, so building one per
        session gives a busy honeypot one pool per session."""
        llm_module.reset_shared_client()
        self.addCleanup(llm_module.reset_shared_client)

        first = llm_module.get_shared_client()
        second = llm_module.get_shared_client()

        self.assertIs(first, second)


class ResponseSizeCapTests(unittest.TestCase):
    def test_oversized_response_is_rejected(self) -> None:
        """A misbehaving endpoint that keeps streaming must not grow the
        buffer without bound."""
        d = MagicMock()
        receiver = llm_module.SimpleResponseReceiver(200, d, max_size=16)
        transport = MagicMock()
        receiver.makeConnection(transport)

        receiver.dataReceived(b"x" * 32)

        self.assertLessEqual(len(receiver.buf), 16)
        transport.stopProducing.assert_called_once()

    def test_normal_response_is_unaffected(self) -> None:
        d = MagicMock()
        receiver = llm_module.SimpleResponseReceiver(200, d, max_size=1024)
        receiver.makeConnection(MagicMock())

        receiver.dataReceived(b'{"ok": true}')
        receiver.connectionLost()

        d.callback.assert_called_once_with((200, b'{"ok": true}'))


class AnthropicDetectionTests(unittest.TestCase):
    def _client(self, host: str) -> llm_module.LLMClient:
        def fake_get(section: str, option: str, **kwargs: object) -> str:
            return host if option == "host" else ""

        with (
            patch.object(CowrieConfig, "get", fake_get),
            patch.object(CowrieConfig, "getint", return_value=500),
            patch.object(CowrieConfig, "getfloat", return_value=0.5),
            patch.object(CowrieConfig, "getboolean", return_value=False),
        ):
            return llm_module.LLMClient()

    def test_real_anthropic_host(self) -> None:
        self.assertTrue(self._client("https://api.anthropic.com").is_anthropic)

    def test_unrelated_host_containing_the_name(self) -> None:
        """A gateway domain that merely contains the text must not be sent
        Anthropic-shaped requests."""
        self.assertFalse(
            self._client("https://anthropic.com.gateway.example/v1").is_anthropic
        )

    def test_openai_host(self) -> None:
        self.assertFalse(self._client("https://api.openai.com").is_anthropic)

    def test_anthropic_request_includes_temperature(self) -> None:
        """The operator's temperature setting must apply to Anthropic too."""
        client = self._client("https://api.anthropic.com")
        body = client._format_request_body(["system", "User: id"])

        self.assertEqual(body["temperature"], 0.5)


class RateLimitTests(unittest.TestCase):
    """Unlike the shell backend's free local simulation, every command in LLM
    mode is a metered API call, so the pace and size are bounded."""

    def _proto(self) -> llm_protocol.HoneyPotBaseProtocol:
        proto = llm_protocol.HoneyPotBaseProtocol(_avatar())
        proto.realClientIP = "203.0.113.9"
        proto.terminal = MagicMock()
        self.client = MagicMock()
        self.client.get_response.return_value = defer.succeed("")
        proto.llm_client = self.client
        proto.command_history = []
        return proto

    def test_commands_are_rate_limited(self) -> None:
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        proto = self._proto()
        with patch.object(llm_protocol, "llm_rate_limiter", limiter):
            for _ in range(5):
                proto._process_command_with_llm("id")

        self.assertEqual(self.client.get_response.call_count, 2)

    def test_exec_commands_are_rate_limited(self) -> None:
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        client = MagicMock()
        client.get_response.return_value = defer.succeed("")
        with (
            patch.object(llm_protocol, "llm_rate_limiter", limiter),
            patch.object(llm_protocol, "get_shared_client", return_value=client),
        ):
            for _ in range(3):
                proto = llm_protocol.HoneyPotExecProtocol(_avatar(), b"id")
                proto.realClientIP = "203.0.113.10"
                proto.terminal = MagicMock()
                proto._process_exec_with_llm()

        self.assertEqual(client.get_response.call_count, 1)

    def test_long_command_is_truncated(self) -> None:
        """An overlong line must not be sent to the API or grow the history
        without bound."""
        proto = self._proto()
        with (
            patch.object(llm_protocol, "MAX_COMMAND_LENGTH", 10),
            patch.object(llm_protocol, "llm_rate_limiter", RateLimiter(max_requests=5)),
        ):
            proto._process_command_with_llm("x" * 50)

        prompt = self.client.get_response.call_args[0][0]
        self.assertEqual(prompt[-1], "User: " + "x" * 10)


if __name__ == "__main__":
    unittest.main()
