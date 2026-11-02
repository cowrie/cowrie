# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: SSH server transport that answers key exchange messages the client
# ABOUTME: did not negotiate with SSH_MSG_UNIMPLEMENTED instead of raising.

from __future__ import annotations

from typing import TYPE_CHECKING

from twisted.conch.ssh import transport

if TYPE_CHECKING:
    from cowrie.core.events import EventLog

GROUP_EXCHANGE_KEX = (
    b"diffie-hellman-group-exchange-sha1",
    b"diffie-hellman-group-exchange-sha256",
)


class KexMessageTransport(transport.SSHServerTransport):
    """
    Twisted dispatches a key exchange message to its handler without
    checking that the message belongs to the negotiated algorithm, or
    that an algorithm was negotiated at all. A group exchange request
    then reaches factory.getDHPrime() even when group exchange was never
    offered, and a message sent before KEXINIT finds no algorithm.

    Such a message is answered with SSH_MSG_UNIMPLEMENTED and otherwise
    ignored, as OpenSSH does, and recorded as a cowrie.client.kex_unexpected
    event. The connection stays open.
    """

    events: EventLog | None = None

    def _negotiated_kex(self) -> bytes | None:
        """The agreed key exchange algorithm, or None before KEXINIT."""
        return getattr(self, "kexAlg", None)

    def _unexpected_kex_message(self, messagenum: int) -> None:
        kex = self._negotiated_kex()
        if self.events:
            self.events.dispatch(
                "cowrie.client.kex_unexpected",
                "Unexpected key exchange message %(messagenum)d for %(kexalg)s; ignored",
                messagenum=messagenum,
                kexalg=kex.decode() if kex is not None else None,
            )
        self.sendUnimplemented()

    def ssh_KEX_DH_GEX_REQUEST_OLD(self, packet: bytes) -> None:
        if self._negotiated_kex() is None:
            self._unexpected_kex_message(transport.MSG_KEX_DH_GEX_REQUEST_OLD)
            return
        super().ssh_KEX_DH_GEX_REQUEST_OLD(packet)

    def ssh_KEX_DH_GEX_REQUEST(self, packet: bytes) -> None:
        if self._negotiated_kex() not in GROUP_EXCHANGE_KEX:
            self._unexpected_kex_message(transport.MSG_KEX_DH_GEX_REQUEST)
            return
        super().ssh_KEX_DH_GEX_REQUEST(packet)

    def ssh_KEX_DH_GEX_INIT(self, packet: bytes) -> None:
        if self._negotiated_kex() not in GROUP_EXCHANGE_KEX:
            self._unexpected_kex_message(transport.MSG_KEX_DH_GEX_INIT)
            return
        super().ssh_KEX_DH_GEX_INIT(packet)
