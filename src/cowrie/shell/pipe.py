# ABOUTME: Manages stdout/stderr routing for shell command execution and pipelines.
# ABOUTME: Handles file redirections, FD duplication, and piped command chains.

from __future__ import annotations

import os
import re
import stat
import time
from typing import Any


from twisted.python import failure, log

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs

# FD target type constants
FD_STDIN = "stdin"
FD_TERMINAL = "terminal"
FD_PIPE = "pipe"
FD_CAPTURE = "capture"
FD_FILE = "file"
FD_FILE_INPUT = "file_input"
FD_DEVNULL = "devnull"


class PipeProtocol:
    def __init__(
        self,
        protocol: Any,
        cmd: Any,
        cmdargs: list[str],
        input_data: bytes | None,
        next_command: Any,
        redirect: bool = False,
        redirections: list[dict[str, Any]] | None = None,
    ) -> None:
        self.cmd = cmd
        self.cmdargs = cmdargs
        self.input_data: bytes | None = input_data
        self.next_command = next_command
        self.data: bytes = b""
        self.redirected_data: bytes = b""
        self.err_data: bytes = b""
        self.protocol = protocol
        self.redirect = redirect  # don't send to terminal if enabled
        self.redirections = redirections or []

        # FD Table: fd -> (type, value)
        # Types: "file", "pipe", "terminal", "devnull"
        self.targets: dict[int, tuple[str, Any]] = {}

        self.redirection_error = False
        self.redirect_real_files: list[tuple[str, str]] = []
        self._stdout_written = 0
        self._stderr_written = 0
        self._setup_redirections()
        self.has_redirection_error = self.redirection_error or (
            getattr(self.next_command, "has_redirection_error", False)
            if self.next_command
            else False
        )
        self.has_redirections = bool(self.redirections)

    def _setup_redirections(self) -> None:
        """Process redirection operations to build the FD table."""
        # Initialize default FDs
        self.targets[0] = (FD_STDIN, None)
        self.targets[1] = (FD_PIPE, None) if self.next_command else (FD_TERMINAL, None)
        self.targets[2] = (FD_TERMINAL, None)

        # If redirect is True (command substitution), stdout default is capture
        if self.redirect:
            self.targets[1] = (FD_CAPTURE, None)

        # Defer stdin reading until after all redirections are processed
        # This ensures that if an output redirection truncates a file also used for input,
        # the input reading sees the truncated (empty) file, matching standard shell behavior.
        pending_stdin_target: str | None = None

        for op in self.redirections:
            if op["type"] == "file":
                fd = op["fd"]
                target = op["target"]
                append = op["append"]
                file_info = self._prepare_output_file(target, append)
                if file_info:
                    if file_info.get("devnull"):
                        self.targets[fd] = (FD_DEVNULL, None)
                    else:
                        self.targets[fd] = (FD_FILE, file_info)
                        if fd == 1:
                            self._stdout_written = file_info.get("start_size", 0)
                        elif fd == 2:
                            self._stderr_written = file_info.get("start_size", 0)

            elif op["type"] == "stdin":
                fd = op["fd"]
                target = op["target"]
                pending_stdin_target = target
                # Stdin is handled by loading input_data, so we don't strictly need it in targets for writing,
                # but we track it for completeness if needed.
                self.targets[fd] = (FD_FILE_INPUT, target)

            elif op["type"] == "dup":
                fd = op["fd"]
                target_fd = op["target"]
                if target_fd in self.targets:
                    self.targets[fd] = self.targets[target_fd]
                else:
                    # If target FD is not open/defined, what to do?
                    # Bash says "Bad file descriptor".
                    # For now, maybe default to terminal or ignore?
                    # Let's ignore to match previous behavior of being lenient, or set to closed?
                    pass

        if pending_stdin_target:
            self._prepare_stdin(pending_stdin_target)

    def _prepare_stdin(self, target: str) -> None:
        """Load stdin from a redirected file path into input_data."""
        try:
            path = self.protocol.fs.resolve_path(target, self.protocol.cwd)
            data = self.protocol.fs.file_contents(path)
        except fs.FileNotFound:
            self._emit_redirection_error(
                f"-bash: {target}: No such file or directory\n"
            )
            return
        except fs.PermissionDenied:
            self._emit_redirection_error(f"-bash: {target}: Permission denied\n")
            return
        else:
            self.input_data = data

    def _prepare_output_file(self, target: str, append: bool) -> dict[str, Any] | None:
        """Resolve and ready an output file, returning metadata for writing."""
        outfile = self.protocol.fs.resolve_path(target, self.protocol.cwd)
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
            "start_size": start_size,
        }

    def _needs_new_backing(self, p: Any) -> bool:
        """Decide whether to create a fresh real file for redirection target."""
        if not p or not p[fs.A_REALFILE]:
            return True
        # Don't modify files from the honeyfs - create new backing instead
        contents_path = CowrieConfig.get(
            "honeypot", "contents_path", fallback="honeyfs"
        )
        return p[fs.A_REALFILE].startswith(contents_path)

    def _create_redirect_target(self, outfile: str) -> str | None:
        """Create a new backing file for a redirected output target."""
        tmp_fname = "{}-{}-{}-redir_{}".format(
            time.strftime("%Y%m%d-%H%M%S"),
            self.protocol.getProtoTransport().transportId,
            self.protocol.terminal.transport.session.id,
            re.sub("[^A-Za-z0-9]", "_", outfile),
        )
        safeoutfile = os.path.join(
            CowrieConfig.get("honeypot", "download_path"), tmp_fname
        )
        perm = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
        try:
            self.protocol.fs.mkfile(
                outfile,
                self.protocol.user.uid,
                self.protocol.user.gid,
                0,
                stat.S_IFREG | perm,
            )
        except fs.FileNotFound:
            self._emit_redirection_error(
                f"-bash: {outfile}: No such file or directory\n"
            )
            return None
        except fs.PermissionDenied:
            self._emit_redirection_error(f"-bash: {outfile}: Permission denied\n")
            return None

        with open(safeoutfile, "ab"):
            self.protocol.fs.update_realfile(
                self.protocol.fs.getfile(outfile), safeoutfile
            )
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
                log.msg(f"Failed to truncate redirect target {safeoutfile}: {e}")
                return None
        return safeoutfile, start_size

    def _emit_redirection_error(self, message: str) -> None:
        """Send a redirection-related error to the terminal and flag failure."""
        self.redirection_error = True
        try:
            self.protocol.terminal.write(message.encode("utf8"))
        except Exception:
            log.msg(message)

    def connectionMade(self) -> None:
        if self.input_data is None:
            self.input_data = b""

    def outReceived(self, data: bytes) -> None:
        """
        Invoked when a command in the chain called 'write' method
        """
        self.write_stdout(data)

    def insert_command(self, command):
        """
        Insert the next command into the list.
        """
        command.next_command = self.next_command
        self.next_command = command

    def errReceived(self, data: bytes) -> None:
        self.write_stderr(data)

    def inConnectionLost(self) -> None:
        pass

    def outConnectionLost(self) -> None:
        """
        Called from HoneyPotBaseProtocol.call_command() to run a next command in the chain
        """

        if self.next_command:
            # self.next_command.input_data = self.data
            npcmd = self.next_command.cmd
            npcmdargs = self.next_command.cmdargs
            self.protocol.call_command(self.next_command, npcmd, *npcmdargs)

    def errConnectionLost(self) -> None:
        pass

    def processExited(self, reason: failure.Failure) -> None:
        log.msg(f"processExited for {self.cmd}, status {reason.value.exitCode}")

    def processEnded(self, reason: failure.Failure) -> None:
        log.msg(f"processEnded for {self.cmd}, status {reason.value.exitCode}")

    def _pipe_to_next(self, data: bytes) -> bool:
        """
        Pass data to the next command in the pipeline if present.
        """
        if not self.next_command:
            return False
        if self.next_command.input_data is None:
            self.next_command.input_data = data
        else:
            self.next_command.input_data += data
        return True

    def _write_to_terminal(self, data: bytes) -> None:
        if self.protocol is not None and self.protocol.terminal is not None:
            self.protocol.terminal.write(data)
        else:
            log.msg("Connection was probably lost. Could not write to terminal")

    def write_stdout(self, data: bytes) -> None:
        self.data = data
        self._write_to_fd(1, data)

    def write_stderr(self, data: bytes) -> None:
        self.err_data = self.err_data + data
        self._write_to_fd(2, data)

    def _write_to_fd(self, fd: int, data: bytes) -> None:
        target = self.targets.get(fd)
        if not target:
            # Fallback or closed
            return

        t_type, t_val = target

        if t_type == FD_TERMINAL:
            self._write_to_terminal(data)
        elif t_type == FD_PIPE:
            self._pipe_to_next(data)
        elif t_type == FD_CAPTURE:
            self.redirected_data += data
        elif t_type == FD_FILE:
            self._write_to_file(t_val, data, is_stdout=(fd == 1))
        elif t_type == FD_DEVNULL:
            pass

    def _write_to_file(
        self, file_info: dict[str, Any], data: bytes, is_stdout: bool
    ) -> None:
        real_path = file_info["real"]
        try:
            with open(real_path, "ab") as f:
                f.write(data)
        except OSError as e:
            log.msg(f"Failed to write redirected output: {e}")
            return

        if is_stdout:
            self._stdout_written += len(data)
            written = self._stdout_written
        else:
            self._stderr_written += len(data)
            written = self._stderr_written

        self.protocol.fs.update_size(file_info["virtual"], written)
