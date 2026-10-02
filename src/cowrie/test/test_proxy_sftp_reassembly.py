# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The SSH proxy reassembles SFTP messages from raw channel bytes; the
# ABOUTME: channel splits and joins them freely, so framing must survive both.

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any
from unittest.mock import MagicMock

from twisted.conch.ssh import filetransfer

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

from cowrie.ssh_proxy.protocols import sftp as proxy_sftp


def _realpath(path: bytes, request_id: int = 1) -> bytes:
    """A framed SSH_FXP_REALPATH message for this path."""
    body = (
        bytes([filetransfer.FXP_REALPATH])
        + request_id.to_bytes(4, "big")
        + len(path).to_bytes(4, "big")
        + path
    )
    return len(body).to_bytes(4, "big") + body


class SftpReassemblyTests(unittest.TestCase):
    """Every scenario must recover the same commands a single unfragmented
    call does; a desync silently blanks SFTP audit logging for the rest of
    the connection."""

    def _sftp(self) -> tuple[Any, list[bytes]]:
        ssh = MagicMock()
        sftp = proxy_sftp.SFTP("uuid", "chan", ssh)
        seen: list[bytes] = []
        original = sftp.handle_packet

        def record(parent: str) -> None:
            original(parent)
            seen.append(sftp.command)

        sftp.handle_packet = record  # type: ignore[method-assign]
        return sftp, seen

    def _feed(
        self, stream: bytes, chunk: int = 0, parent: str = "[CLIENT]"
    ) -> list[bytes]:
        sftp, seen = self._sftp()
        if chunk:
            for i in range(0, len(stream), chunk):
                sftp.parse_packet(parent, stream[i : i + chunk])
        else:
            sftp.parse_packet(parent, stream)
        return seen

    def test_single_message_in_one_call(self) -> None:
        self.assertEqual(self._feed(_realpath(b"/tmp/one")), [b"cd /tmp/one"])

    def test_single_message_byte_by_byte(self) -> None:
        self.assertEqual(self._feed(_realpath(b"/tmp/one"), chunk=1), [b"cd /tmp/one"])

    def test_single_message_in_unaligned_chunks(self) -> None:
        """A client whose channel writes don't line up with message
        boundaries: the 4-byte header itself arrives split."""
        self.assertEqual(self._feed(_realpath(b"/tmp/one"), chunk=7), [b"cd /tmp/one"])

    def test_two_coalesced_messages(self) -> None:
        """Ordinary TCP behaviour: a second message's bytes land on the end of
        the same read."""
        stream = _realpath(b"/tmp/one", 1) + _realpath(b"/tmp/two", 2)

        self.assertEqual(self._feed(stream), [b"cd /tmp/one", b"cd /tmp/two"])

    def test_three_coalesced_messages(self) -> None:
        stream = (
            _realpath(b"/tmp/one", 1)
            + _realpath(b"/tmp/two", 2)
            + _realpath(b"/tmp/three", 3)
        )

        self.assertEqual(
            self._feed(stream), [b"cd /tmp/one", b"cd /tmp/two", b"cd /tmp/three"]
        )

    def test_coalesced_and_fragmented(self) -> None:
        stream = _realpath(b"/tmp/one", 1) + _realpath(b"/tmp/two", 2)

        self.assertEqual(self._feed(stream, chunk=7), [b"cd /tmp/one", b"cd /tmp/two"])

    def test_client_and_server_streams_are_independent(self) -> None:
        """The two directions have their own reassembly state; interleaving
        them must not mix their bytes."""
        sftp, seen = self._sftp()
        client = _realpath(b"/tmp/client")
        server = _realpath(b"/tmp/server")

        # Half of each, then the remainder, alternating directions.
        sftp.parse_packet("[CLIENT]", client[:6])
        sftp.parse_packet("[SERVER]", server[:6])
        sftp.parse_packet("[CLIENT]", client[6:])
        sftp.parse_packet("[SERVER]", server[6:])

        self.assertEqual(seen, [b"cd /tmp/client", b"cd /tmp/server"])


if __name__ == "__main__":
    unittest.main()
