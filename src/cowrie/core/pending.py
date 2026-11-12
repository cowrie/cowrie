# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: A queue that holds items until its consumer is ready, then delivers
# ABOUTME: the held items and every later one in arrival order.

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

T = TypeVar("T")


class PendingQueue(Generic[T]):
    """Holds items for a consumer that is not ready yet.

    The proxies use this for traffic that arrives before the other side can
    take it: the frontend talks before the backend is connected, or the
    backend talks before the frontend has logged in. Until release() is
    called, put() holds each item. release() delivers the held items in
    order, and from then on put() delivers straight away.
    """

    def __init__(self, deliver: Callable[[T], None]) -> None:
        self._deliver = deliver
        self._held: deque[T] = deque()
        self._draining = False
        self.released = False

    def put(self, item: T) -> None:
        self._held.append(item)
        if self.released:
            self._drain()

    def release(self) -> None:
        self.released = True
        self._drain()

    def _drain(self) -> None:
        # A delivery can call put() again (the consumer answers at once). The
        # outer drain picks that item up after the ones already held, so order
        # is kept and the stack does not grow.
        if self._draining:
            return
        self._draining = True
        try:
            while self._held:
                self._deliver(self._held.popleft())
        finally:
            self._draining = False
