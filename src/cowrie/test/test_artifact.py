# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/core/artifact.py content-addressed storage.
# ABOUTME: Verifies the duplicate flag set when close() dedupes by SHA-256.

from __future__ import annotations

import os
import tempfile
import unittest

from cowrie.core.artifact import Artifact
from cowrie.test.config_override import override_config


class ArtifactDuplicateTests(unittest.TestCase):
    """close() must record whether the content already existed on disk."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        override_config(self, "honeypot", "download_path", self.tmpdir)

    def tearDown(self) -> None:
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def test_saved_in_download_path_configured_at_creation(self) -> None:
        """The download path is read when the artifact is created, not when
        the module is imported."""
        a = Artifact("first")
        a.write(b"content")
        a.close()
        self.assertEqual(os.path.dirname(a.shasumFilename), self.tmpdir)

    def test_first_capture_is_not_duplicate(self) -> None:
        a = Artifact("first")
        a.write(b"unique-content-1")
        a.close()
        self.assertFalse(a.duplicate)

    def test_identical_content_is_duplicate(self) -> None:
        first = Artifact("first")
        first.write(b"same-bytes")
        first.close()

        second = Artifact("second")
        second.write(b"same-bytes")
        second.close()

        self.assertFalse(first.duplicate)
        self.assertTrue(second.duplicate)

    def test_empty_artifact_is_not_duplicate(self) -> None:
        a = Artifact("empty")
        a.close()
        self.assertFalse(a.duplicate)


if __name__ == "__main__":
    unittest.main()
