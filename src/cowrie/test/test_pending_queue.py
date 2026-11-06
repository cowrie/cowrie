# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for PendingQueue, which holds items until its consumer is ready
# ABOUTME: and then delivers them, and everything after, in arrival order.

from __future__ import annotations

import unittest

from cowrie.core.pending import PendingQueue


class PendingQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.delivered: list[bytes] = []
        self.queue: PendingQueue[bytes] = PendingQueue(self.delivered.append)

    def test_holds_items_until_released(self) -> None:
        self.queue.put(b"a")
        self.queue.put(b"b")

        self.assertEqual(self.delivered, [])
        self.assertFalse(self.queue.released)

    def test_release_delivers_held_items_in_order(self) -> None:
        self.queue.put(b"a")
        self.queue.put(b"b")

        self.queue.release()

        self.assertEqual(self.delivered, [b"a", b"b"])
        self.assertTrue(self.queue.released)

    def test_delivers_immediately_once_released(self) -> None:
        self.queue.release()

        self.queue.put(b"a")

        self.assertEqual(self.delivered, [b"a"])

    def test_second_release_delivers_nothing_again(self) -> None:
        self.queue.put(b"a")
        self.queue.release()

        self.queue.release()

        self.assertEqual(self.delivered, [b"a"])

    def test_item_put_during_release_keeps_its_place(self) -> None:
        # Delivering a held item can make the consumer answer, which puts a
        # new item while the release is still draining. It must go after the
        # items that were already held.
        def deliver(item: bytes) -> None:
            self.delivered.append(item)
            if item == b"a":
                queue.put(b"reply")

        queue: PendingQueue[bytes] = PendingQueue(deliver)
        queue.put(b"a")
        queue.put(b"b")

        queue.release()

        self.assertEqual(self.delivered, [b"a", b"b", b"reply"])
