
from __future__ import annotations

import os
import re
import stat
import time
from typing import Any


from twisted.python import failure, log

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs


class StdOutStdErrEmulationProtocol:
    """
    Pipe support written by Dave Germiquet
    Support for commands chaining added by Ivan Korolev (@fe7ch)
    """

    __author__ = "davegermiquet"

    def __init__(
        self,
        protocol: Any,
        cmd: Any,
        cmdargs: list[str],
        input_data: bytes | None,
        next_command: Any,
        redirect: bool = False,
        redirections: dict[str, Any] | None = None,
    ) -> None:
        self.cmd = cmd
        self.cmdargs = cmdargs
        self.input_data: bytes | None = input_data
        self.next_command = next_command
        self.data: bytes = b""
        self.redirected_data: bytes = b""
        self.err_data: bytes = b""
        self.protocol = protocol
        self.redirect = redirect  # dont send to terminal if enabled
        self.redirections = redirections or {
            "files": [],
            "fd_mappings": {},
            "stdin": None,
            "has_redirections": False,
        }
        self.stdout_file: dict[str, Any] | None = None
        self.stderr_file: dict[str, Any] | None = None
        self.stdout_to_stderr = False
        self.stderr_to_stdout = False
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
        self.has_redirections = bool(self.redirections.get("has_redirections"))
        self.write_stdout = self._write_stdout
        self.write_stderr = self._write_stderr

    def _setup_redirections(self) -> None:
        """Prepare stdin/stdout/stderr file handles and fd mappings."""
        fd_mappings = self.redirections.get("fd_mappings", {})
        self.stderr_to_stdout = fd_mappings.get(2) == 1
        self.stdout_to_stderr = fd_mappings.get(1) == 2

        stdin_info = self.redirections.get("stdin")
        if stdin_info:
            self._prepare_stdin(stdin_info)

        for entry in self.redirections.get("files", []):
            fd = entry.get("fd")
            target = entry.get("target")
            append = entry.get("append", False)
            if fd is None or target is None:
                continue
            if fd == 1:
                self.stdout_file = self._prepare_output_file(target, append)
                if self.stdout_file:
                    self._stdout_written = self.stdout_file.get("start_size", 0)
            elif fd == 2:
                self.stderr_file = self._prepare_output_file(target, append)
                if self.stderr_file:
                    self._stderr_written = self.stderr_file.get("start_size", 0)

    def _prepare_stdin(self, stdin_info: dict[str, Any]) -> None:
        """Load stdin from a redirected file path into input_data."""
        target = stdin_info.get("target")
        if target is None:
            return

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

    def _prepare_output_file(
        self, target: str, append: bool
    ) -> dict[str, Any] | None:
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
        return not p or not p[fs.A_REALFILE] or p[fs.A_REALFILE].startswith("honeyfs")

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
        self._write_stdout(data)

    def insert_command(self, command):
        """
        Insert the next command into the list.
        """
        command.next_command = self.next_command
        self.next_command = command

    def errReceived(self, data: bytes) -> None:
        self._write_stderr(data)

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

    def _write_stdout(self, data: bytes, from_stderr: bool = False) -> None:
        self.data = data

        if self.stdout_to_stderr and not from_stderr:
            self._write_stderr(data, redirected=True)
            return

        if self.stdout_file:
            self._write_to_file(self.stdout_file, data, is_stdout=True)
            return

        if self._pipe_to_next(data):
            return

        if self.redirect:
            # Used for command substitutions
            self.redirected_data += data
            return

        self._write_to_terminal(data)

    def _write_stderr(self, data: bytes, redirected: bool = False) -> None:
        self.err_data = self.err_data + data

        if self.stderr_to_stdout and not redirected:
            # Duplicate stderr to stdout destinations (e.g., 2>&1)
            if self.stdout_file:
                self._write_to_file(self.stdout_file, data, is_stdout=True)
                return
            if self._pipe_to_next(data):
                return
            if self.redirect:
                self.redirected_data += data
                return
            if self.protocol and self.protocol.terminal:
                self.protocol.terminal.write(data)
            return

        if self.stderr_file:
            self._write_to_file(self.stderr_file, data, is_stdout=False)
            return

        if self.protocol and self.protocol.terminal:
            self.protocol.terminal.write(data)

    def _write_to_file(
        self, file_info: dict[str, Any], data: bytes, is_stdout: bool
    ) -> None:
        if file_info.get("devnull"):
            return

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
