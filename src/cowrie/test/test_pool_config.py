# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for backend_pool.util.read_pool_config — operator override cascade
# ABOUTME: covers the pool-configs cwd-or-bundled lookup

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from backend_pool import util

ENV_PATH = "COWRIE_BACKEND_POOL_CONFIG_FILES_PATH"


class ReadPoolConfigTests(unittest.TestCase):
    """read_pool_config cascades operator override to the bundled pool_configs/."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._prior_env = os.environ.get(ENV_PATH)
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        if self._prior_env is None:
            os.environ.pop(ENV_PATH, None)
        else:
            os.environ[ENV_PATH] = self._prior_env

    def test_returns_bundled_when_override_unset(self) -> None:
        os.environ.pop(ENV_PATH, None)

        xml = util.read_pool_config("default_filter.xml")

        self.assertIn("<filter", xml)

    def test_operator_override_wins(self) -> None:
        (Path(self.tmpdir) / "default_filter.xml").write_text("<custom/>")
        os.environ[ENV_PATH] = self.tmpdir

        self.assertEqual(util.read_pool_config("default_filter.xml"), "<custom/>")

    def test_missing_in_override_falls_through_to_bundled(self) -> None:
        os.environ[ENV_PATH] = self.tmpdir  # empty dir

        xml = util.read_pool_config("default_filter.xml")

        self.assertIn("<filter", xml)

    def test_missing_everywhere_raises(self) -> None:
        os.environ[ENV_PATH] = self.tmpdir

        with self.assertRaises(FileNotFoundError):
            util.read_pool_config("does-not-exist.xml")
