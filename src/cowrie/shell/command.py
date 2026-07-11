# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2018-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
This module contains code to run a command
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Callable

from twisted.internet import error
from twisted.logger import Logger
from twisted.python import failure


def process_status(code: int) -> failure.Failure:
    """A process-end reason carrying an exit status.

    ``ProcessDone`` for 0 (a clean exit) and ``ProcessTerminated`` otherwise, so
    the SSH session relays the right ``exit-status`` to the client.
    """
    if code == 0:
        return failure.Failure(error.ProcessDone(status=""))
    return failure.Failure(error.ProcessTerminated(exitCode=code))


class HoneyPotCommand:
    """
    This is the super class for all commands in cowrie/commands
    """

    _log = Logger()

    # True once exit() has run. An async callback firing after the command
    # already exited (a download completing after an abort) checks this so a
    # late exit() is a no-op. Class-level so it holds even for instances
    # created without __init__ (tests).
    exited: bool = False

    @property
    def current_user(self) -> dict[str, str | int]:
        """
        Get the current effective user info.
        Returns effective_user from the nearest shell in cmdstack (set by su)
        if present, otherwise returns the session user's info.
        """
        # Search cmdstack for a shell with effective_user (from su)
        # Walk from top to bottom of stack
        for item in reversed(self.protocol.cmdstack):
            if hasattr(item, "effective_user") and item.effective_user:
                return dict(item.effective_user)
        # Fall back to session user
        return {
            "uid": self.protocol.user.uid,
            "gid": self.protocol.user.gid,
            "username": self.protocol.user.username,
            "home": self.protocol.user.avatar.home,
        }

    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = list(args)
        # Exit status, propagated to the owning shell on exit() for $? and
        # && / || . Commands set this (default 0 = success).
        self.exit_code: int = 0
        self.environ = self.protocol.cmdstack[-1].environ
        self.exported = self.protocol.cmdstack[-1].exported
        self.fs = self.protocol.fs
        self.data: bytes = b""  # output data
        self.input_data: None | (
            bytes
        ) = None  # used to store STDIN data passed via PIPE
        pp: Any = getattr(self.protocol, "pp", None)
        self.writefn: Callable[[bytes], None]
        self.errorWritefn: Callable[[bytes], None]
        if pp and hasattr(pp, "write_stdout") and hasattr(pp, "write_stderr"):
            self.writefn = cast("Callable[[bytes], None]", pp.write_stdout)
            self.errorWritefn = cast("Callable[[bytes], None]", pp.write_stderr)
        else:
            self.writefn = cast("Callable[[bytes], None]", self.protocol.pp.outReceived)
            self.errorWritefn = cast(
                "Callable[[bytes], None]", self.protocol.pp.errReceived
            )

    def write(self, data: str) -> None:
        """
        Write a string to the user on stdout
        """
        self.writefn(data.encode("utf8"))

    def writeBytes(self, data: bytes) -> None:
        """
        Like write() but input is bytes
        """
        self.writefn(data)

    def errorWrite(self, data: str) -> None:
        """
        Write errors to the user on stderr
        """
        self.errorWritefn(data.encode("utf8"))

    def check_arguments(self, application, args):
        files = []
        for arg in args:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if self.fs.isdir(path):
                self.errorWrite(
                    f"{application}: error reading `{arg}': Is a directory\n"
                )
                continue
            files.append(path)
        return files

    def set_input_data(self, data: bytes) -> None:
        self.input_data = data

    def start(self) -> None:
        self.call()
        self.exit()

    def call(self) -> None:
        self.write(f"Hello World! [{self.args!r}]\n")

    def exit(self, code: int | None = None) -> None:
        """
        Sometimes client is disconnected and command exits after. So cmdstack is gone

        ``code`` sets this command's exit status (``$?`` for the shell that ran
        it). When omitted, the existing ``exit_code`` is kept, so a command that
        set it earlier (e.g. in an error callback) can just call ``exit()``.

        Exiting twice is safe: a second call (a download callback firing after
        the command already exited) returns without touching the cmdstack, so
        the shell is not resumed again.
        """
        if self.exited:
            return
        self.exited = True
        if code is not None:
            self.exit_code = code
        if (
            self.protocol
            and self.protocol.terminal
            and hasattr(self.protocol, "pp")
            and getattr(self.protocol.pp, "redirect_real_files", None)
        ):
            for real_path, virtual_path in self.protocol.pp.redirect_real_files:
                self.protocol.terminal.redirFiles.add((real_path, virtual_path))

        if len(self.protocol.cmdstack):
            self.protocol.cmdstack.remove(self)

        if len(self.protocol.cmdstack):
            # Hand the exit status to the shell that ran us, for $? and the
            # && / || logic in runCommand.
            self.protocol.cmdstack[-1].last_exit_code = self.exit_code
            self.protocol.cmdstack[-1].resume()
        else:
            # No shell left to return to: either an `exit` builtin removed the
            # shell before this command finished, or the session is being torn
            # down. End the process with this command's status.
            ret = process_status(self.exit_code)
            # The session could be disconnected already, when this happens .transport is gone
            try:
                self.protocol.terminal.transport.processEnded(ret)
            except AttributeError:
                pass

    def handle_CTRL_C(self) -> None:
        self._log.info("Received CTRL-C, exiting..")
        self.write("^C\n")
        self.exit(130)  # 128 + SIGINT, like a real shell

    def lineReceived(self, line: str) -> None:
        self._log.info("QUEUED INPUT: {line}", line=line)
        # Queue on the innermost shell, the next stdin reader once this
        # command exits: an outer shell only resumes after the shells above
        # it unwind, so a line queued there would wait on the whole stack.
        for item in reversed(self.protocol.cmdstack):
            if hasattr(item, "queue_line"):
                item.queue_line(line)
                return

    def resume(self) -> None:
        pass

    def handle_TAB(self) -> None:
        pass

    def eofReceived(self) -> None:
        """
        EOF on stdin. Commands that read stdin override this to terminate; the
        default ignores it (the command does not read stdin).
        """
        pass

    def __repr__(self) -> str:
        return str(self.__class__.__name__)
