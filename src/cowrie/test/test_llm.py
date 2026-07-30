# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the LLM backend: attacker input and operator config must
# ABOUTME: not crash a session, and API calls are shared, capped and limited.

from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch

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
        with patch.object(llm_protocol.CowrieConfig, "get", return_value="hi {nope}"):
            context = proto._build_system_context()

        self.assertIn("svr04", context)

    def test_unbalanced_brace_in_template(self) -> None:
        """An unmatched brace raises ValueError rather than KeyError; it must
        be tolerated the same way."""
        proto = self._proto()
        with patch.object(llm_protocol.CowrieConfig, "get", return_value="hi {"):
            context = proto._build_system_context()

        self.assertIn("svr04", context)

    def test_supported_placeholders_still_substituted(self) -> None:
        proto = self._proto()
        with patch.object(
            llm_protocol.CowrieConfig, "get", return_value="host={hostname} cwd={cwd}"
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
            patch.object(llm_module.CowrieConfig, "get", fake_get),
            patch.object(llm_module.CowrieConfig, "getint", return_value=500),
            patch.object(llm_module.CowrieConfig, "getfloat", return_value=0.5),
            patch.object(llm_module.CowrieConfig, "getboolean", return_value=False),
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


if __name__ == "__main__":
    unittest.main()
