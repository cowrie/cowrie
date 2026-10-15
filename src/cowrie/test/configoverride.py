# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Sets a CowrieConfig option for the duration of one test and restores
# ABOUTME: the previous state on cleanup, so tests do not leak config to each other.

from __future__ import annotations

from typing import TYPE_CHECKING

from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    import unittest


def override_option(
    test: unittest.TestCase, section: str, option: str, value: str
) -> None:
    """Set ``option`` in ``section`` until ``test`` finishes. Cleanup restores
    the previous value, or removes the option, and removes a section this
    call had to create."""
    if not CowrieConfig.has_section(section):
        CowrieConfig.add_section(section)
        test.addCleanup(CowrieConfig.remove_section, section)
    old = CowrieConfig.get(section, option, fallback=None)
    CowrieConfig.set(section, option, value)
    if old is None:
        test.addCleanup(CowrieConfig.remove_option, section, option)
    else:
        test.addCleanup(CowrieConfig.set, section, option, old)
