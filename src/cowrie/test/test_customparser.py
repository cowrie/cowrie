# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that CustomParser raises its termination exceptions correctly.
# ABOUTME: error() must raise OptionNotFound and exit() must raise ExitException.

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from cowrie.shell.customparser import CustomParser, ExitException, OptionNotFound


class TestCustomParser(unittest.TestCase):
    """CustomParser.error/exit must raise usable exceptions, not TypeError."""

    def _parser(self) -> CustomParser:
        return CustomParser(MagicMock())

    def test_error_raises_option_not_found_with_message(self) -> None:
        parser = self._parser()
        with self.assertRaises(OptionNotFound) as cm:
            parser.error("bad option")
        self.assertEqual(cm.exception.value, "bad option")

    def test_exit_raises_exit_exception(self) -> None:
        parser = self._parser()
        with self.assertRaises(ExitException):
            parser.exit()


if __name__ == "__main__":
    unittest.main()
