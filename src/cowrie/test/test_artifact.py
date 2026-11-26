# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for cowrie/core/artifact.py content-addressed storage, the
# ABOUTME: duplicate flag, and how open artifacts are ended when idle or at shutdown.

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

from twisted.internet.task import Clock

from cowrie.core import artifact as artifact_module
from cowrie.core.artifact import (
    Artifact,
    abort_open_artifacts,
    store_leftover_artifacts,
)


class ArtifactDuplicateTests(unittest.TestCase):
    """close() must record whether the content already existed on disk."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self._orig_artifact_dir = Artifact.artifactDir
        Artifact.artifactDir = self.tmpdir

    def tearDown(self) -> None:
        Artifact.artifactDir = self._orig_artifact_dir
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

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


class ArtifactLifetimeTests(unittest.TestCase):
    """An open artifact is ended when no data arrives for idle_timeout
    seconds, or when cowrie shuts down, so no temp file is left behind."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.clock = Clock()
        patches: tuple[Any, ...] = (
            patch.object(Artifact, "artifactDir", self.tmpdir),
            patch.object(Artifact, "idle_timeout", 60),
            patch.object(artifact_module, "reactor", self.clock),
            # Only this test's artifacts, not ones other tests left open.
            patch.object(Artifact, "open_artifacts", set()),
        )
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._remove_tmpdir)

    def _remove_tmpdir(self) -> None:
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def test_idle_artifact_is_aborted_and_stored(self) -> None:
        aborted: list[bool] = []
        a = Artifact("idle")
        a.on_abort = lambda: aborted.append(True)
        a.write(b"first")
        self.clock.advance(59)
        a.write(b"second")
        self.clock.advance(59)
        self.assertEqual(aborted, [])

        self.clock.advance(1)

        self.assertEqual(aborted, [True])
        self.assertTrue(a.closed)
        self.assertEqual(os.listdir(self.tmpdir), [a.shasum])

    def test_idle_artifact_without_owner_is_closed(self) -> None:
        a = Artifact("idle")

        self.clock.advance(60)

        self.assertTrue(a.closed)
        self.assertEqual(os.listdir(self.tmpdir), [])

    def test_failing_abort_still_closes(self) -> None:
        def broken() -> None:
            raise RuntimeError

        a = Artifact("idle")
        a.on_abort = broken

        with patch.object(artifact_module, "_log") as log:
            self.clock.advance(60)

        self.assertTrue(a.closed)
        log.failure.assert_called_once()
        self.assertIn("Stopping the transfer", log.failure.call_args.args[0])

    def test_close_stops_the_idle_deadline(self) -> None:
        aborted: list[bool] = []
        a = Artifact("done")
        a.on_abort = lambda: aborted.append(True)
        a.close()

        self.clock.advance(120)

        self.assertEqual(aborted, [])
        self.assertEqual(self.clock.getDelayedCalls(), [])

    def test_data_after_the_artifact_ended_is_dropped(self) -> None:
        # A transfer can still deliver a chunk after its artifact ended it;
        # that chunk must not fail on the closed file.
        a = Artifact("ended")
        a.write(b"kept")
        a.abort()

        a.write(b"late")

        with open(a.shasumFilename, "rb") as f:
            self.assertEqual(f.read(), b"kept")

    def test_zero_idle_timeout_never_aborts(self) -> None:
        with patch.object(Artifact, "idle_timeout", 0):
            a = Artifact("unbounded")

        self.clock.advance(3600)

        self.assertFalse(a.closed)
        a.close()

    def test_shutdown_aborts_every_open_artifact(self) -> None:
        aborted: list[str] = []
        done = Artifact("done")
        done.on_abort = lambda: aborted.append("done")
        done.close()
        running = []
        for label in ("one", "two"):
            a = Artifact(label)
            a.on_abort = lambda label=label: aborted.append(label)
            a.write(label.encode())
            running.append(a)

        abort_open_artifacts()

        self.assertEqual(sorted(aborted), ["one", "two"])
        self.assertTrue(all(a.closed for a in running))
        self.assertEqual(
            sorted(os.listdir(self.tmpdir)), sorted(a.shasum for a in running)
        )


class LeftoverArtifactTests(unittest.TestCase):
    """At startup, temp files a killed or crashed run left behind are stored
    under their SHA-256, or removed when empty. Other files are untouched."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(self._remove_tmpdir)

    def _remove_tmpdir(self) -> None:
        for name in os.listdir(self.tmpdir):
            os.remove(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    def _file(self, name: str, data: bytes) -> None:
        with open(os.path.join(self.tmpdir, name), "wb") as f:
            f.write(data)

    def test_leftover_temp_files_are_stored_or_removed(self) -> None:
        self._file("tmpab_cd123", b"partial sample")
        self._file("tmp0000empt", b"")
        for other in ("notes.txt", "tmpshort", "wget-download_1234", "tmpABCDEFGH"):
            self._file(other, b"keep")

        store_leftover_artifacts(self.tmpdir)

        stored = hashlib.sha256(b"partial sample").hexdigest()
        self.assertEqual(
            sorted(os.listdir(self.tmpdir)),
            sorted(
                [stored, "notes.txt", "tmpshort", "wget-download_1234", "tmpABCDEFGH"]
            ),
        )
        with open(os.path.join(self.tmpdir, stored), "rb") as f:
            self.assertEqual(f.read(), b"partial sample")

    def test_leftover_already_captured_is_removed(self) -> None:
        stored = hashlib.sha256(b"sample").hexdigest()
        self._file(stored, b"sample")
        self._file("tmpzzzzzzzz", b"sample")

        store_leftover_artifacts(self.tmpdir)

        self.assertEqual(os.listdir(self.tmpdir), [stored])


if __name__ == "__main__":
    unittest.main()
