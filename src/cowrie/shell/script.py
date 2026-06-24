# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Shared helpers for running an uploaded file as a shell script:
# ABOUTME: binary-vs-script detection and executing the contents through the shell.

"""
Running uploaded code is a core honeypot job: a second-stage downloader is
usually a shell script dropped by ``wget`` / ``curl`` / ``tftp`` and then run as
``./x``, ``sh x`` or via a shebang. This module concentrates the two decisions
that path needs, so ``bash``/``sh`` and direct ``./file`` execution behave the
same:

* :func:`is_executable_binary` -- tell an ELF/PE/Mach-O or otherwise binary
  payload from a text script, so we refuse to "run" a binary instead of feeding
  its bytes to the parser (as both a real kernel and ``bash`` do).
* :func:`run_script_file` -- read the file from the emulated filesystem and run
  its contents through a fresh :class:`~cowrie.shell.honeypot.HoneyPotShell`.
  The whole text is handed to the parser unchanged: the grammar treats newlines
  as separators and ``#`` lines (including the shebang) as comments, so loops,
  conditionals and functions that span lines are emulated rather than flattened.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cowrie.shell.fs import FileNotFound

if TYPE_CHECKING:
    from cowrie.shell.command import HoneyPotCommand

# How deep one script may invoke another (a script that runs a script ...),
# guarding against runaway or self-referential droppers.
MAX_SCRIPT_DEPTH = 5

# Magic numbers for common executable formats that are clearly not scripts.
_BINARY_MAGIC = (
    b"\x7fELF",  # ELF (Linux, the usual malware case)
    b"MZ",  # DOS / PE (Windows)
    b"\xca\xfe\xba\xbe",  # Mach-O universal / Java class
    b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
    b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit (LE)
    b"\xce\xfa\xed\xfe",  # Mach-O 32-bit (LE)
)

# How much of the file to inspect for NUL bytes / decodability.
_SAMPLE_BYTES = 8192


def is_executable_binary(contents: bytes) -> bool:
    """Return True if ``contents`` looks like a binary executable, not a script.

    A shell script is text: ASCII, or otherwise valid UTF-8. So anything with
    a known executable magic number, a NUL byte, or bytes that are not valid
    UTF-8 is treated as a binary -- which covers ELF/PE/Mach-O droppers and
    packed payloads while leaving non-ASCII (e.g. UTF-8 comment) scripts alone.
    """
    if not contents:
        return False
    if contents.startswith(_BINARY_MAGIC):
        return True

    sample = contents[:_SAMPLE_BYTES]
    if b"\x00" in sample:
        return True

    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def run_script_file(
    command: HoneyPotCommand,
    path: str,
    *,
    not_found_message: str,
    binary_message: str,
) -> None:
    """Read ``path`` from the emulated filesystem and run it as a shell script.

    ``not_found_message`` / ``binary_message`` are the errors to write (with the
    caller's preferred ``bash:`` / ``-bash:`` prefix) when the file is missing or
    is an executable binary. The command's ``exit_code`` is set to the status of
    the last command the script ran.
    """
    # Imported here to avoid a circular import at module load (honeypot does not
    # depend on this module, but protocol -> honeypot -> ... -> this would).
    from cowrie.shell.honeypot import HoneyPotShell

    protocol = command.protocol
    depth = getattr(protocol, "_script_depth", 0)
    if depth >= MAX_SCRIPT_DEPTH:
        command.errorWrite(f"-bash: {path}: too many levels of recursion\n")
        return

    try:
        contents = command.fs.file_contents(path)
    except (FileNotFound, FileNotFoundError):
        command.errorWrite(not_found_message)
        return

    if is_executable_binary(contents):
        command.errorWrite(binary_message)
        return

    text = contents.decode("utf-8", errors="replace")
    if not text.strip():
        return

    protocol._script_depth = depth + 1
    try:
        shell = HoneyPotShell(protocol, interactive=False)
        protocol.cmdstack.append(shell)
        # Hand the whole script to the parser: newlines separate statements and
        # "#" lines (the shebang included) are comments, so flow control that
        # spans lines is emulated rather than joined onto one line.
        shell.lineReceived(text)
        command.exit_code = shell.last_exit_code
        protocol.cmdstack.pop()
    finally:
        protocol._script_depth = depth
