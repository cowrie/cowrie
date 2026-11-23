# SPDX-FileCopyrightText: 2016-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Stores honeypot artifacts (uploads, downloads, piped input) under their
# ABOUTME: SHA-256, and ends any left open: when no data arrives for a while, or at shutdown.

"""
This module contains code to handling saving of honeypot artifacts
These will typically be files uploaded to the honeypot and files
downloaded inside the honeypot, or input being piped in.

Code behaves like a normal Python file handle.

Example:

    with Artifact(name) as f:
        f.write("abc")

or:

    g = Artifact("testme2")
    g.write("def")
    g.close()

"""

from __future__ import annotations

import hashlib
import os
import tempfile
import uuid
from typing import TYPE_CHECKING, Any, ClassVar

from twisted.internet import reactor
from twisted.logger import Logger

from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    from twisted.internet.interfaces import IDelayedCall

_log = Logger()


def temp_download_path(prefix: str) -> str:
    """A unique download-dir path for a temp file that is renamed to its
    sha256 or serves as honeyfs realfile backing once written. The name
    carries no session or attacker-controlled text, only the prefix."""
    return os.path.join(
        CowrieConfig.get("honeypot", "download_path", fallback="."),
        f"{prefix}_{uuid.uuid4().hex}",
    )


def abort_open_artifacts() -> None:
    """End every artifact still open, as cowrie shuts down. Each owner stops
    its transfer and reports it while sessions still exist; whatever arrived
    is stored, so no temp file is left behind."""
    for artifact in list(Artifact.open_artifacts):
        artifact.abort()


class Artifact:
    artifactDir: str = CowrieConfig.get("honeypot", "download_path", fallback=".")
    # Seconds without new data after which an open artifact is ended; 0 means never.
    idle_timeout: int = CowrieConfig.getint(
        "honeypot", "download_idle_timeout", fallback=60
    )
    open_artifacts: ClassVar[set[Artifact]] = set()

    def __init__(self, label: str) -> None:
        self.label: str = label

        self.fp = tempfile.NamedTemporaryFile(  # pylint: disable=R1732
            dir=self.artifactDir, delete=False
        )
        self.tempFilename = self.fp.name
        self.closed: bool = False

        self.shasum: str = ""
        self.shasumFilename: str = ""
        self.duplicate: bool = False

        # Set by the owner of the transfer that fills this artifact: stops the
        # transfer and reports it as failed. Without one, ending only closes.
        self.on_abort: Callable[[], None] | None = None
        self._idle_call: IDelayedCall | None = None
        if self.idle_timeout > 0:
            self._idle_call = reactor.callLater(self.idle_timeout, self.abort)
        Artifact.open_artifacts.add(self)

    def __enter__(self) -> Any:
        return self.fp

    def __exit__(
        self,
        etype: type[BaseException] | None,
        einst: BaseException | None,
        etrace: TracebackType | None,
    ) -> bool:
        self.close()
        return True

    def write(self, data: bytes) -> None:
        if self.closed:
            # A transfer can still deliver data after its artifact was ended;
            # what was stored stays as it is.
            return
        self.fp.write(data)
        if self._idle_call is not None and self._idle_call.active():
            self._idle_call.reset(self.idle_timeout)

    def abort(self) -> None:
        """End this artifact before its transfer finished: let the owner stop
        the transfer, then store whatever arrived."""
        if self.closed:
            return
        _log.info(
            "Ending unfinished artifact {label} after {size} bytes",
            label=self.label,
            size=self.fp.tell(),
        )
        if self.on_abort is not None:
            try:
                self.on_abort()
            except Exception:
                _log.failure(
                    "Stopping the transfer for {label} failed", label=self.label
                )
        self.close()

    def fileno(self) -> Any:
        return self.fp.fileno()

    def close(self, keepEmpty: bool = False) -> tuple[str, str] | None:
        if self.closed:
            # Closing is idempotent: a command can close on its normal path and
            # again on exit() without the second call failing on the closed file.
            return None
        if self._idle_call is not None and self._idle_call.active():
            self._idle_call.cancel()
        Artifact.open_artifacts.discard(self)
        size: int = self.fp.tell()
        if size == 0 and not keepEmpty:
            self.fp.close()
            self.closed = True
            try:
                os.remove(self.fp.name)
            except FileNotFoundError:
                pass
            return None

        self.fp.seek(0)
        data = self.fp.read()
        self.fp.close()
        self.closed = True

        self.shasum = hashlib.sha256(data).hexdigest()
        self.shasumFilename = os.path.join(self.artifactDir, self.shasum)

        if os.path.exists(self.shasumFilename):
            # Content already captured; drop the temp copy. The dedup outcome is
            # reported once, congruently, on the caller's file_download event
            # (duplicate=True) rather than as a separate log line here.
            os.remove(self.fp.name)
            self.duplicate = True
        else:
            os.rename(self.fp.name, self.shasumFilename)
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(self.shasumFilename, 0o666 & ~umask)
            self.duplicate = False

        return self.shasum, self.shasumFilename
