# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/scripts/cowrie.py — the cowrie start/stop entry point
# ABOUTME: covers the init-marker check on cowrie start

from __future__ import annotations

import contextlib
import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cowrie.scripts import cowrie as cowrie_script


class CheckInitializedTests(unittest.TestCase):
    """check_initialized refuses to proceed unless cwd has a cowrie config."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._prior_cwd = os.getcwd()
        os.chdir(self.tmpdir)
        self.addCleanup(os.chdir, self._prior_cwd)

    def test_accepts_etc_cowrie_cfg(self) -> None:
        (Path(self.tmpdir) / "etc").mkdir()
        (Path(self.tmpdir) / "etc" / "cowrie.cfg").write_text("")

        cowrie_script.check_initialized()  # should not raise

    def test_accepts_etc_cowrie_cfg_dist(self) -> None:
        (Path(self.tmpdir) / "etc").mkdir()
        (Path(self.tmpdir) / "etc" / "cowrie.cfg.dist").write_text("")

        cowrie_script.check_initialized()  # should not raise

    def test_refuses_when_neither_present(self) -> None:
        stderr = io.StringIO()
        with (
            contextlib.redirect_stdout(stderr),
            self.assertRaises(SystemExit) as ctx,
        ):
            cowrie_script.check_initialized()

        self.assertEqual(ctx.exception.code, 1)
        self.assertIn("not initialised", stderr.getvalue())
