# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Overrides one cowrie config option for the duration of a test,
# ABOUTME: through the environment variable CowrieConfig checks first.

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import patch

from cowrie.core.config import to_environ_key

if TYPE_CHECKING:
    import unittest


def override_config(
    test: unittest.TestCase, section: str, option: str, value: str
) -> None:
    """Set [section] option to value until the test finishes."""
    key = to_environ_key(f"cowrie_{section}_{option}")
    env = patch.dict(os.environ, {key: value})
    env.start()
    test.addCleanup(env.stop)
