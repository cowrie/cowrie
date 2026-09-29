# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The csirtg output plugin reads its token when it starts, so
# ABOUTME: importing it neither exits nor depends on the config at import time.

from __future__ import annotations

import importlib
import os
import sys
import types
import unittest

from cowrie.core.config import CowrieConfig

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

try:
    import csirtgsdk  # noqa: F401
except ImportError:
    # The SDK is an optional dependency; stub it so the plugin imports.
    sys.modules["csirtgsdk"] = types.ModuleType("csirtgsdk")

SECTION = "output_csirtg"


class CsirtgConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        if not CowrieConfig.has_section(SECTION):
            CowrieConfig.add_section(SECTION)
            self.addCleanup(CowrieConfig.remove_section, SECTION)
        for option, value in {
            "token": "a1b2c3d4",
            "username": "user",
            "feed": "feed",
            "description": "cowrie",
        }.items():
            self._set(option, value)
        old_token = os.environ.get("CSIRTG_TOKEN")
        if old_token is None:
            self.addCleanup(os.environ.pop, "CSIRTG_TOKEN", None)
        else:
            self.addCleanup(os.environ.__setitem__, "CSIRTG_TOKEN", old_token)

    def _set(self, option: str, value: str) -> None:
        old = CowrieConfig.get(SECTION, option, fallback=None)
        CowrieConfig.set(SECTION, option, value)
        if old is None:
            self.addCleanup(CowrieConfig.remove_option, SECTION, option)
        else:
            self.addCleanup(CowrieConfig.set, SECTION, option, old)

    def _import(self) -> types.ModuleType:
        sys.modules.pop("cowrie.output.csirtg", None)
        return importlib.import_module("cowrie.output.csirtg")

    def test_import_without_token_does_not_exit(self) -> None:
        """Only an enabled plugin needs a token; importing the module must
        not end the process."""
        self._import()

    def test_start_uses_token_set_after_import(self) -> None:
        csirtg = self._import()
        self._set("token", "token-after-import")

        csirtg.Output()

        self.assertEqual(os.environ["CSIRTG_TOKEN"], "token-after-import")


if __name__ == "__main__":
    unittest.main()
