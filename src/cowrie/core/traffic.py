# SPDX-FileCopyrightText: 2026 sudu787
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Counts the bytes a connection sends, for the totals that
# ABOUTME: cowrie.session.closed reports as bytes_in and bytes_out.

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable


class _TrafficCounter(Protocol):
    bytes_out: int


class CountingTransport:
    """Wrap a connection's transport so every byte written to it is counted
    on ``owner.bytes_out``. Attribute access falls through to the wrapped
    transport, so getPeer(), sessionno, loseConnection() and the rest work
    as before. The owner counts received bytes itself, in dataReceived().
    """

    def __init__(self, transport: Any, owner: _TrafficCounter) -> None:
        self._transport = transport
        self._owner = owner

    def write(self, data: bytes) -> None:
        self._owner.bytes_out += len(data)
        self._transport.write(data)

    def writeSequence(self, data: Iterable[bytes]) -> None:
        chunks = list(data)
        self._owner.bytes_out += sum(len(c) for c in chunks)
        self._transport.writeSequence(chunks)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._transport, name)
