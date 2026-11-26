# SPDX-FileCopyrightText: 2025-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Manages stdout/stderr routing for shell command execution and pipelines.
# ABOUTME: Handles file redirections, FD duplication, and piped command chains.

from __future__ import annotations

import stat
from typing import TYPE_CHECKING, Any

from twisted.logger import Logger

from cowrie.core.artifact import temp_download_path
from cowrie.shell import fs

if TYPE_CHECKING:
    from twisted.python import failure

# FD target type constants
FD_STDIN = "stdin"
FD_TERMINAL = "terminal"
FD_CAPTURE = "capture"
FD_FILE = "file"
FD_FILE_INPUT = "file_input"
FD_DEVNULL = "devnull"

# The terminal's output streams. A terminal target names the stream it writes
# to, so a duplicated fd (2>&1) keeps writing to the stream it was copied from.
TERMINAL_STDOUT = (FD_TERMINAL, 1)
TERMINAL_STDERR = (FD_TERMINAL, 2)

# bash 5.3's builtins (`compgen -b`). An error a builtin reports carries the
# shell's prefix ("-bash: echo: ..."); an external command reports under the
# name it was run by ("uname: ...").
BASH_BUILTINS = frozenset(
    ". : [ alias bg bind break builtin caller cd command compgen complete "
    "compopt continue declare dirs disown echo enable eval exec exit export "
    "false fc fg getopts hash help history jobs kill let local logout mapfile "
    "popd printf pushd pwd read readarray readonly return set shift shopt "
    "source suspend test times trap true type typeset ulimit umask unalias "
    "unset wait".split()
)

# Soft limit on open file descriptors (ulimit -n). A redirection naming an fd at
# or above this is rejected by bash with "Bad file descriptor"; valid fds are
# 0 .. MAX_OPEN_FILES - 1.
MAX_OPEN_FILES = 1024


class PipeProtocol:
    _log = Logger()

    def __init__(
        self,
        protocol: Any,
        cmd: Any,
        cmdargs: list[str],
        input_data: bytes | None,
        base_targets: dict[int, tuple[str, Any]] | None = None,
        redirections: list[dict[str, Any]] | None = None,
        *,
        cwd: str,
        user: dict[str, Any],
        error_prefix: str = "-bash: ",
    ) -> None:
        self.cmd = cmd
        # The name the command was invoked by (argv[0]), when a shell starts it.
        self.argv0: str | None = None
        # How the shell that opens the redirections names itself in errors
        # ("-bash: " at a login prompt, "bash: line 3: " under bash -c).
        self.error_prefix = error_prefix
        self.cmdargs = cmdargs
        self.input_data: bytes | None = input_data
        # Working directory and user identity of the shell that started this
        # command: redirection targets resolve against the cwd, and the files
        # they create are owned by the user.
        self.cwd = cwd
        self.user = user
        # Assignments written before the command name (`IFS=: read ...`),
        # which hold for this command only
        self.assignments: dict[str, str] = {}
        # True when ``input_data`` came from a pipe (an upstream pipeline
        # stage); stdin is then closed (EOF) once it is read, as no terminal
        # will ever feed it.
        self.stdin_from_pipe: bool = False
        self.protocol = protocol
        # The command inherits its shell's output fds (1, 2 and any higher
        # ones open), as a forked process inherits its parent's open files,
        # then applies its own redirections on top. Without them it writes to
        # the terminal.
        self.base_targets = base_targets
        self.redirections = redirections or []

        # FD Table: fd -> (type, value). Types: "terminal", "capture" (value
        # is a bytearray sink), "file" (value is a file_info dict), "devnull".
        self.targets: dict[int, tuple[str, Any]] = {}

        self.redirection_error = False
        self.redirect_real_files: list[tuple[str, str]] = []
        # Set once a write finds the client gone, so a command that keeps
        # writing (a download's progress meter) logs the loss only once
        self.terminal_lost = False
        # Set once the command wrote to a closed stdout; the write failed and
        # was reported, and the command ends with a failure status.
        self.stdout_write_failed = False
        self._setup_redirections()
        self.has_redirection_error = self.redirection_error

    def output_fds(self) -> dict[int, tuple[str, Any]]:
        """The fd table without stdin: what a shell this command starts, or a
        group these redirections apply to, writes through."""
        return {fd: target for fd, target in self.targets.items() if fd != 0}

    def _out_of_range_fd(self, op: dict[str, Any]) -> int | None:
        """Return the first file descriptor in ``op`` that exceeds the open-file
        limit, which bash rejects with "Bad file descriptor", or None.

        A redirection like ``9999>file`` parses fine but names an fd the process
        cannot open; ``2>&9999`` likewise duplicates from one. Only a ``dup``'s
        ``target`` is an fd (a ``file`` / ``stdin`` target is a path).
        """
        candidates = [op["fd"]]
        if op["type"] == "dup":
            candidates.append(op["target"])
        for fd in candidates:
            if isinstance(fd, int) and fd >= MAX_OPEN_FILES:
                return fd
        return None

    def _setup_redirections(self) -> None:
        """Process redirection operations to build the FD table."""
        # Inherit the shell's output fds as they are, including a closed
        # stdout or stderr, or without them write to the terminal; then apply
        # this command's own redirections on top.
        self.targets[0] = (FD_STDIN, None)
        if self.base_targets is None:
            self.targets[1] = TERMINAL_STDOUT
            self.targets[2] = TERMINAL_STDERR
        else:
            self.targets.update(self.base_targets)

        # Defer reading stdin until all redirections are processed, so that
        # when an output redirection truncates the file also used for input
        # (`cat < f > f`) the read sees the truncated file, as in a real shell.
        # The file is still looked up in order, so a missing one is reported
        # in its place among the other redirection errors. The last input
        # redirection wins (`cat < f <<EOF` reads the here-document): a path
        # to read, or the bytes of a here-document.
        pending_stdin: str | bytes | None = None

        # bash applies redirections left to right and stops at the first one
        # that fails; the command does not run (POSIX XCU 2.8.1).
        for op in self.redirections:
            bad_fd = self._out_of_range_fd(op)
            if bad_fd is None and op["type"] == "dup":
                if op["target"] not in self.targets:
                    bad_fd = op["target"]
            if bad_fd is not None:
                self._emit_redirection_error(
                    f"{self.error_prefix}{bad_fd}: Bad file descriptor\n"
                )
                break

            if op["type"] == "file":
                fd = op["fd"]
                target = op["target"]
                append = op["append"]
                file_info = self._prepare_output_file(target, append)
                if file_info is None:
                    break
                if file_info.get("devnull"):
                    self.targets[fd] = (FD_DEVNULL, None)
                else:
                    self.targets[fd] = (FD_FILE, file_info)

            elif op["type"] == "stdin":
                fd = op["fd"]
                target = op["target"]
                path = self._open_stdin(target)
                if path is None:
                    break
                pending_stdin = path
                # Stdin is handled by loading input_data, so we don't strictly need it in targets for writing,
                # but we track it for completeness if needed.
                self.targets[fd] = (FD_FILE_INPUT, target)

            elif op["type"] == "heredoc":
                pending_stdin = op["data"]
                self.targets[op["fd"]] = (FD_FILE_INPUT, "<<")

            elif op["type"] == "dup":
                fd = op["fd"]
                self.targets[fd] = self.targets[op["target"]]

            elif op["type"] == "close":
                self.targets.pop(op["fd"], None)

        if isinstance(pending_stdin, str):
            self.input_data = self.protocol.fs.file_contents(pending_stdin)
        elif pending_stdin is not None:
            self.input_data = pending_stdin

    def _open_stdin(self, target: str) -> str | None:
        """Resolve a stdin redirection's file, or report it missing and return
        None."""
        path: str = self.protocol.fs.resolve_path(target, self.cwd)
        if not self.protocol.fs.exists(path):
            self._emit_redirection_error(
                f"{self.error_prefix}{target}: No such file or directory\n"
            )
            return None
        return path

    def _prepare_output_file(self, target: str, append: bool) -> dict[str, Any] | None:
        """Resolve and ready an output file, returning metadata for writing."""
        outfile = self.protocol.fs.resolve_path(target, self.cwd)
        p = self.protocol.fs.getfile(outfile)
        if outfile == "/dev/null":
            return {
                "virtual": outfile,
                "real": None,
                "append": append,
                "start_size": 0,
                "devnull": True,
            }
        start_size = p[fs.A_SIZE] if p and append else 0

        if self._needs_new_backing(p):
            safeoutfile = self._create_redirect_target(outfile)
            if safeoutfile is None:
                return None
            # The fresh backing file starts empty, even for an append.
            start_size = 0
        else:
            reuse = self._reuse_existing_backing(outfile, p, append)
            if reuse is None:
                return None
            safeoutfile, start_size = reuse

        self.redirect_real_files.append((safeoutfile, outfile))
        return {
            "virtual": outfile,
            "real": safeoutfile,
            "append": append,
            "written": start_size,
        }

    def _needs_new_backing(self, p: Any) -> bool:
        """Decide whether a redirection needs a fresh backing file.

        Only backing files this connection created for its own writes are
        written in place. Every other backing file is read-only: honeyfs
        files and downloads, which point into the hash store. A redirection
        to one of those gets a fresh, empty backing file, so neither the
        honeyfs nor a stored sample ever changes.
        """
        if not p or not p[fs.A_REALFILE]:
            return True
        return p[fs.A_REALFILE] not in self.protocol.fs.backing_files

    def _create_redirect_target(self, outfile: str) -> str | None:
        """Create a new backing file for a redirected output target."""
        # The backing file is renamed to its sha256 once the session ends
        # and session attribution travels with the event, so the name only
        # needs to be unique (#40351).
        safeoutfile = temp_download_path("redir")
        perm = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
        try:
            self.protocol.fs.mkfile(
                outfile,
                self.user["uid"],
                self.user["gid"],
                0,
                stat.S_IFREG | perm,
            )
        except fs.FileNotFound:
            self._emit_redirection_error(
                f"{self.error_prefix}{outfile}: No such file or directory\n"
            )
            return None
        except fs.PermissionDenied:
            self._emit_redirection_error(
                f"{self.error_prefix}{outfile}: Permission denied\n"
            )
            return None

        with open(safeoutfile, "ab"):
            self.protocol.fs.update_realfile(
                self.protocol.fs.getfile(outfile), safeoutfile
            )
        self.protocol.fs.backing_files.add(safeoutfile)
        return safeoutfile

    def _reuse_existing_backing(
        self, outfile: str, p: Any, append: bool
    ) -> tuple[str, int] | None:
        """Reuse an existing backing file, truncating if needed."""
        safeoutfile = p[fs.A_REALFILE]
        start_size = p[fs.A_SIZE] if append else 0
        if not append:
            try:
                open(safeoutfile, "wb").close()
                self.protocol.fs.update_size(outfile, 0)
                start_size = 0
            except OSError as e:
                self._log.info(
                    "Failed to truncate redirect target {outfile}: {error}",
                    outfile=safeoutfile,
                    error=e,
                )
                return None
        return safeoutfile, start_size

    def _emit_redirection_error(self, message: str) -> None:
        """Report a failed redirection on stderr and flag failure. As in bash,
        stderr is fd 2 as the redirections before the failed one left it."""
        self.redirection_error = True
        self._write_to_fd(2, message.encode("utf8"))

    def connectionMade(self) -> None:
        if self.input_data is None:
            self.input_data = b""

    def outReceived(self, data: bytes) -> None:
        """
        Invoked when a command in the chain called 'write' method
        """
        self.write_stdout(data)

    def errReceived(self, data: bytes) -> None:
        self.write_stderr(data)

    def inConnectionLost(self) -> None:
        pass

    def errConnectionLost(self) -> None:
        pass

    def processExited(self, reason: failure.Failure) -> None:
        self._log.info(
            "processExited for {cmd}, status {status}",
            cmd=self.cmd,
            status=reason.value.exitCode,
        )

    def processEnded(self, reason: failure.Failure) -> None:
        self._log.info(
            "processEnded for {cmd}, status {status}",
            cmd=self.cmd,
            status=reason.value.exitCode,
        )

    def _write_to_terminal(self, stream: int, data: bytes) -> None:
        if self.protocol is not None and self.protocol.terminal is not None:
            if stream == 2:
                self.protocol.terminal.writeStderr(data)
            else:
                self.protocol.terminal.write(data)
        elif not self.terminal_lost:
            self.terminal_lost = True
            self._log.info("Connection was probably lost. Could not write to terminal")

    def write_stdout(self, data: bytes) -> None:
        self._write_to_fd(1, data)

    def write_stderr(self, data: bytes) -> None:
        self._write_to_fd(2, data)

    def _write_to_fd(self, fd: int, data: bytes) -> None:
        target = self.targets.get(fd)
        if not target:
            # A closed fd: the write fails. Only a failed write to stdout is
            # reported, as a real command checks that one.
            if fd == 1 and data:
                self._report_closed_stdout()
            return

        t_type, t_val = target

        if t_type == FD_TERMINAL:
            self._write_to_terminal(t_val, data)
        elif t_type == FD_CAPTURE:
            # The sink is a bytearray shared by every command writing to this
            # fd (a capture subshell, or a pipeline stage feeding the next).
            t_val += data
        elif t_type == FD_FILE:
            self._write_to_file(t_val, data)
        elif t_type == FD_DEVNULL:
            pass

    def _report_closed_stdout(self) -> None:
        """Report, once, that the command wrote to a closed stdout, the way
        the command itself would (see HoneyPotCommand.closed_stdout_error)."""
        if self.stdout_write_failed:
            return
        self.stdout_write_failed = True
        name = self.argv0 or ""
        prefix = self.error_prefix if name in BASH_BUILTINS else ""
        message = self.cmd.closed_stdout_error
        self._write_to_fd(2, f"{prefix}{name}: {message}\n".encode())

    def _write_to_file(self, file_info: dict[str, Any], data: bytes) -> None:
        real_path = file_info["real"]
        try:
            with open(real_path, "ab") as f:
                f.write(data)
        except OSError as e:
            self._log.info("Failed to write redirected output: {error}", error=e)
            return

        # The write offset lives in the shared file record, so several commands
        # redirected to the same file (a group's `{ ...; } > f`) keep a correct
        # cumulative size, as they share one inherited fd in a real shell.
        file_info["written"] += len(data)
        self.protocol.fs.update_size(file_info["virtual"], file_info["written"])
