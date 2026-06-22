# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the MISP output plugin's malware-sample handling.
# ABOUTME: Ensures downloaded files are looked up by MD5 so sightings register.

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from unittest.mock import MagicMock

try:
    from cowrie.output.misp import Output, file_md5

    have_misp = True
except ImportError:
    have_misp = False


@unittest.skipIf(not have_misp, "pymisp not installed")
class TestFileMd5(unittest.TestCase):
    """file_md5 returns the MD5 hex digest of a file's contents."""

    def test_file_md5(self) -> None:
        data = b"cowrie malware sample\n"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        self.addCleanup(os.remove, path)
        self.assertEqual(file_md5(path), hashlib.md5(data).hexdigest())


@unittest.skipIf(not have_misp, "pymisp not installed")
class TestMispMalwareSample(unittest.TestCase):
    """A downloaded file must be looked up in MISP by its MD5 hash."""

    def _make_output(self) -> tuple[Output, MagicMock]:
        # Bypass start(), which would connect to a live MISP server.
        output = Output.__new__(Output)
        misp_api = MagicMock()
        output.misp_api = misp_api
        output.session_tracking = {}
        output.debug = False
        output.handle_sessions = True
        output.publish = False
        return output, misp_api

    def test_file_download_lookup_uses_md5(self) -> None:
        data = b"malicious payload"
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            outfile = f.name
        self.addCleanup(os.remove, outfile)

        output, misp_api = self._make_output()
        misp_api.search.return_value = {"Attribute": []}

        output.write(
            {
                "eventid": "cowrie.session.file_download",
                "session": "abc123",
                "src_ip": "10.0.0.1",
                "outfile": outfile,
                "shasum": "deadbeef",
            }
        )

        misp_api.search.assert_called_once()
        kwargs = misp_api.search.call_args.kwargs
        self.assertEqual(kwargs["type_attribute"], "malware-sample")
        self.assertEqual(kwargs["value"], hashlib.md5(data).hexdigest())

    def test_missing_outfile_skips_lookup(self) -> None:
        output, misp_api = self._make_output()

        output.write(
            {
                "eventid": "cowrie.session.file_download",
                "session": "abc123",
                "src_ip": "10.0.0.1",
                "outfile": "/nonexistent/path/file",
                "shasum": "deadbeef",
            }
        )

        misp_api.search.assert_not_called()


if __name__ == "__main__":
    unittest.main()
