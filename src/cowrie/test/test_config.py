# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: tests for cowrie/core/config.py — config loader and bundled defaults
# ABOUTME: covers bundled cowrie.cfg.dist seeding and user-file overlay order

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cowrie.core.config import get_config_path, readConfigFile


class ReadConfigFileTests(unittest.TestCase):
    """readConfigFile seeds bundled cowrie.cfg.dist before overlaying user files."""

    def test_bundled_defaults_load_with_no_user_file(self) -> None:
        parser = readConfigFile([])

        # cowrie.cfg.dist defines [honeypot] and related sections.
        self.assertIn("honeypot", parser.sections())
        self.assertEqual(
            parser.get("honeypot", "hostname", fallback="<missing>"), "svr04"
        )

    def test_user_file_overlays_bundled_default(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".cfg", delete=False
        ) as f:
            f.write("[honeypot]\nhostname = myoverride\n")
            user_cfg = f.name
        self.addCleanup(os.unlink, user_cfg)

        parser = readConfigFile([user_cfg])

        self.assertEqual(parser.get("honeypot", "hostname"), "myoverride")
        # Other keys still come from the bundled defaults.
        self.assertIn("log_path", parser["honeypot"])


class GetConfigPathTests(unittest.TestCase):
    """get_config_path returns cwd-relative operator files in priority order."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self._prior_cwd = os.getcwd()
        os.chdir(self.tmpdir)
        self.addCleanup(os.chdir, self._prior_cwd)

    def test_returns_empty_when_no_operator_files_present(self) -> None:
        # No /etc/cowrie/cowrie.cfg expected in the test environment.
        self.assertEqual(get_config_path(), [])

    def test_finds_cwd_etc_cowrie_cfg(self) -> None:
        (Path(self.tmpdir) / "etc").mkdir()
        (Path(self.tmpdir) / "etc" / "cowrie.cfg").write_text("[honeypot]\n")

        self.assertIn("etc/cowrie.cfg", get_config_path())

    def test_finds_cwd_flat_cowrie_cfg(self) -> None:
        (Path(self.tmpdir) / "cowrie.cfg").write_text("[honeypot]\n")

        self.assertIn("cowrie.cfg", get_config_path())
