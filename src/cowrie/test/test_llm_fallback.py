# SPDX-FileCopyrightText: 2026 Aryamann Srivastava
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: With [shell] llm_fallback on, a command that is not emulated is
# ABOUTME: answered by the LLM; every failure ends in "command not found".

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from twisted.internet import defer

from cowrie.llm.protocol import llm_rate_limiter
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.configoverride import override_option
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class FakeLLMClient:
    """Stands in for LLMClient: records the prompts, returns the given answers."""

    def __init__(self, *answers: str | Exception) -> None:
        self.answers = list(answers)
        self.prompts: list[list[str]] = []

    def get_response(self, prompt: list[str]) -> defer.Deferred[str]:
        self.prompts.append(prompt)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            return defer.fail(answer)
        return defer.succeed(answer)


class LLMFallbackTests(unittest.TestCase):
    def setUp(self) -> None:
        llm_rate_limiter.cache_clear()
        self.addCleanup(llm_rate_limiter.cache_clear)
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def enable(self, client: FakeLLMClient) -> None:
        override_option(self, "shell", "llm_fallback", "true")
        patcher = mock.patch("cowrie.llm.llm.get_shared_client", return_value=client)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_line(self, line: bytes) -> bytes:
        self.tr.clear()
        self.proto.lineReceived(line + b"\n")
        output: bytes = self.tr.value()
        self.assertTrue(output.endswith(PROMPT), output)
        return output[: -len(PROMPT)]

    def test_off_by_default(self) -> None:
        client = FakeLLMClient("never used")
        patcher = mock.patch("cowrie.llm.llm.get_shared_client", return_value=client)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.assertEqual(
            self.run_line(b"foobar --flag"), b"-bash: foobar: command not found\n"
        )
        self.assertEqual(client.prompts, [])

    def test_unknown_command_is_answered(self) -> None:
        client = FakeLLMClient("foobar 1.2.3")
        self.enable(client)
        self.assertEqual(self.run_line(b"foobar --version"), b"foobar 1.2.3\n")
        self.assertEqual(len(client.prompts), 1)
        self.assertEqual(client.prompts[0][-1], "User: foobar --version")

    def test_the_model_sees_the_files_of_the_current_directory(self) -> None:
        client = FakeLLMClient("ok")
        self.enable(client)
        self.run_line(b"touch notes.txt report.pdf")
        self.run_line(b"foobar")
        system = client.prompts[0][0]
        self.assertIn("notes.txt", system)
        self.assertIn("report.pdf", system)
        self.assertIn("'/root'", system)
        self.assertIn("'unitTest'", system)
        self.assertIn("untrusted user", system)

    def test_markdown_is_removed(self) -> None:
        self.enable(FakeLLMClient("```\nfirst\nsecond\n```"))
        self.assertEqual(self.run_line(b"foobar"), b"first\nsecond\n")

    def test_emulated_commands_do_not_use_the_model(self) -> None:
        client = FakeLLMClient("never used")
        self.enable(client)
        self.assertEqual(self.run_line(b"echo hi"), b"hi\n")
        self.assertEqual(client.prompts, [])

    def test_paths_do_not_use_the_model(self) -> None:
        client = FakeLLMClient("never used")
        self.enable(client)
        self.assertEqual(
            self.run_line(b"./payload"), b"-bash: ./payload: No such file or directory\n"
        )
        self.assertEqual(client.prompts, [])

    def test_an_empty_answer_is_command_not_found(self) -> None:
        self.enable(FakeLLMClient(""))
        self.assertEqual(
            self.run_line(b"foobar; echo $?"),
            b"-bash: foobar: command not found\n127\n",
        )

    def test_an_api_error_is_command_not_found(self) -> None:
        self.enable(FakeLLMClient(RuntimeError("boom")))
        self.assertEqual(
            self.run_line(b"foobar; echo $?"),
            b"-bash: foobar: command not found\n127\n",
        )

    def test_a_good_answer_has_status_zero(self) -> None:
        self.enable(FakeLLMClient("done"))
        self.assertEqual(self.run_line(b"foobar; echo $?"), b"done\n0\n")

    def test_the_rate_limit_is_command_not_found(self) -> None:
        override_option(self, "llm", "rate_limit_requests", "1")
        override_option(self, "llm", "rate_limit_window", "60")
        llm_rate_limiter.cache_clear()
        client = FakeLLMClient("first answer", "never used")
        self.enable(client)
        self.assertEqual(self.run_line(b"foobar"), b"first answer\n")
        self.assertEqual(self.run_line(b"foobar"), b"-bash: foobar: command not found\n")
        self.assertEqual(len(client.prompts), 1)

    def test_later_answers_see_the_earlier_ones(self) -> None:
        client = FakeLLMClient("answer one", "answer two")
        self.enable(client)
        self.run_line(b"alpha")
        self.run_line(b"beta")
        self.assertEqual(
            client.prompts[1][1:],
            ["User: alpha", "System: answer one", "User: beta"],
        )

    def test_redirection_and_pipes_work(self) -> None:
        self.enable(FakeLLMClient("to a file", "through a pipe"))
        self.run_line(b"foobar > out.txt")
        self.assertEqual(self.run_line(b"cat out.txt"), b"to a file\n")
        self.assertEqual(self.run_line(b"foobar | cat"), b"through a pipe\n")

    def test_a_long_command_line_is_cut(self) -> None:
        override_option(self, "llm", "max_command_length", "20")
        client = FakeLLMClient("ok")
        self.enable(client)
        self.run_line(b"foobar " + b"a" * 100)
        self.assertEqual(len(client.prompts[0][-1]), len("User: ") + 20)


if __name__ == "__main__":
    unittest.main()
