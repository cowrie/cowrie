# SPDX-FileCopyrightText: 2026 Aryamann Srivastava
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Optional fallback for commands that Cowrie does not emulate: an LLM
# ABOUTME: answers them, given the files of the virtual current directory.

"""
The hybrid mode. The shell keeps emulating every command it knows. When a plain
command name is not found, and ``[shell] llm_fallback`` is enabled, the command
is sent to the LLM configured in the ``[llm]`` section instead of failing with
"command not found". Any problem (rate limit, API error, empty answer) ends in
the normal "command not found" message, so the option can only add answers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from twisted.logger import Logger

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from twisted.python import failure

# How many entries of the current directory are shown to the model
MAX_LISTING = 50
# How many earlier fallback answers are kept, so later answers can agree with them
MAX_HISTORY = 5


def fallback_enabled() -> bool:
    """Whether commands that are not found are sent to the LLM."""
    return CowrieConfig.getboolean("shell", "llm_fallback", fallback=False)


def fallback_applies(cmd: str) -> bool:
    """Only a plain command name is sent. A path (``./x``, ``/tmp/x``) is a file
    the attacker brought, and the model should not invent what it prints."""
    return fallback_enabled() and bool(cmd) and "/" not in cmd


class Command_llm_fallback(HoneyPotCommand):
    """Run a command that is not emulated by asking the LLM what it would print."""

    _log = Logger()

    def start(self) -> None:
        # Imported here so that the LLM modules are only loaded when the option is used
        from cowrie.llm.llm import get_shared_client
        from cowrie.llm.protocol import llm_rate_limiter, max_command_length

        self.name: str = getattr(self.pp, "argv0", "") or ""
        src_ip = getattr(self.protocol, "realClientIP", "")
        if not llm_rate_limiter().check(src_ip):
            self._log.info(
                "LLM rate limit exceeded for {src_ip}, not calling the API",
                src_ip=src_ip,
            )
            self.not_found()
            return

        line = " ".join([self.name, *self.args])[: max_command_length()]
        prompt = [
            self.system_prompt(),
            *self.history_messages(self.history()),
            f"User: {line}",
        ]
        self.line = line

        d = get_shared_client().get_response(prompt)
        d.addCallback(self.answered)
        d.addErrback(self.failed)

    def history(self) -> list[tuple[str, str]]:
        """The earlier fallback commands of this session and their answers."""
        if not hasattr(self.protocol, "llm_fallback_history"):
            setattr(self.protocol, "llm_fallback_history", [])  # noqa: B010
        history: list[tuple[str, str]] = getattr(self.protocol, "llm_fallback_history")  # noqa: B009
        return history

    def system_prompt(self) -> str:
        from cowrie.llm.protocol import PROMPT_INJECTION_GUIDANCE

        try:
            entries = sorted(
                entry[fs.A_NAME] for entry in self.fs.get_path(self.cwd)
            )
        except (fs.FileNotFound, IndexError):
            entries = []
        listing = ", ".join(entries[:MAX_LISTING]) or "(empty)"
        if len(entries) > MAX_LISTING:
            listing += f", and {len(entries) - MAX_LISTING} more"
        hostname = getattr(self.protocol, "hostname", "localhost")
        return (
            "You are simulating a Linux server that has been accessed via SSH. "
            f"The hostname is '{hostname}' and the user is '{self.user['username']}'. "
            f"The current working directory is '{self.cwd}' and it contains exactly "
            f"these entries: {listing}. "
            "The user typed a command that is not one of the standard tools of the "
            "shell. Respond with ONLY the output that command would print on this "
            "system, with no explanation and no formatting. If the command would not "
            "exist on a normal Linux server, answer with the usual "
            "'command not found' error. Do not invent files in the current "
            "directory." + PROMPT_INJECTION_GUIDANCE
        )

    @staticmethod
    def history_messages(history: list[tuple[str, str]]) -> list[str]:
        """Earlier fallback commands and answers, oldest first."""
        messages: list[str] = []
        for line, answer in history[-MAX_HISTORY:]:
            messages.append(f"User: {line}")
            messages.append(f"System: {answer}")
        return messages

    def answered(self, response: str) -> None:
        from cowrie.llm.protocol import strip_markdown

        answer = strip_markdown(response) if response else ""
        if not answer:
            self.not_found()
            return
        history = self.history()
        history.append((self.line, answer))
        del history[:-MAX_HISTORY]
        self.write(answer + "\n")
        self.exit()

    def failed(self, err: failure.Failure) -> None:
        self._log.failure("LLM fallback error", failure=err)
        self.not_found()

    def not_found(self) -> None:
        """Print what the shell prints for a command that does not exist."""
        self.errorWrite(self.shell.command_not_found_message(self.name))
        self.exit(127)
