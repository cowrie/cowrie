# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Test helper that drives the global reactor from synchronous tests,
# ABOUTME: so assertions on real network I/O stay in the test body.

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from twisted.internet import reactor as _reactor

if TYPE_CHECKING:
    from collections.abc import Callable


def pump(predicate: Callable[[], object], timeout: float = 5.0) -> bool:
    """Run the reactor until ``predicate()`` is true, or ``timeout`` elapses.

    Tests doing real network I/O need the reactor to turn. The suite runs
    under plain unittest (see CLAUDE.md), which ignores a returned Deferred:
    a test that schedules its assertions with callLater and returns a
    Deferred never runs them at all. Driving the reactor here keeps the
    assertions in the test body where they execute.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        _reactor.iterate(0.01)
    return bool(predicate())
