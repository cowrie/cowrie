# SPDX-FileCopyrightText: 2026 Aditya Singh
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that every backend pool producer iteration runs on a worker
# ABOUTME: thread and that the timer for the next one is armed by the reactor.

from __future__ import annotations

import unittest
from threading import Lock
from unittest.mock import MagicMock, patch

from twisted.internet.defer import Deferred

from backend_pool.pool_service import PoolService

PRODUCER_STEPS = (
    "__producer_mark_timed_out",
    "__producer_destroy_timed_out",
    "__producer_check_health",
    "__producer_remove_destroyed",
    "__producer_create_guests",
    "__producer_mark_available",
)


def _service() -> PoolService:
    """A PoolService without libvirt, just enough to exercise the loop."""
    service = PoolService.__new__(PoolService)
    service.guests = []
    service.guest_lock = Lock()
    service.loop_sleep_time = 5
    service.loop_next_call = None
    # The steps themselves are not under test and need a live QEMU backend.
    for step in PRODUCER_STEPS:
        setattr(service, f"_PoolService{step}", MagicMock())
    return service


class ProducerLoopThreadingTests(unittest.TestCase):
    @patch("backend_pool.pool_service.threads")
    @patch("backend_pool.pool_service.reactor")
    def test_iteration_touches_no_reactor_api_from_the_worker_thread(
        self, reactor_mock: MagicMock, threads_mock: MagicMock
    ) -> None:
        service = _service()

        service.producer_loop()

        # callLater is not thread safe, and a timer that calls producer_loop
        # directly would put the blocking libvirt and nmap work back on the
        # reactor thread.
        reactor_mock.callLater.assert_not_called()

    @patch("backend_pool.pool_service.threads")
    @patch("backend_pool.pool_service.reactor")
    def test_worker_completion_arms_the_next_iteration(
        self, reactor_mock: MagicMock, threads_mock: MagicMock
    ) -> None:
        service = _service()
        finished: Deferred[None] = Deferred()
        threads_mock.deferToThread.return_value = finished

        service._producer_start()

        threads_mock.deferToThread.assert_called_once_with(service.producer_loop)
        # No timer is armed while the iteration is still running.
        reactor_mock.callLater.assert_not_called()

        finished.callback(None)

        reactor_mock.callLater.assert_called_once_with(5, service._producer_start)
        self.assertIs(service.loop_next_call, reactor_mock.callLater.return_value)

    @patch("backend_pool.pool_service.threads")
    @patch("backend_pool.pool_service.reactor")
    def test_start_pool_runs_the_first_iteration_on_a_worker_thread(
        self, reactor_mock: MagicMock, threads_mock: MagicMock
    ) -> None:
        service = _service()
        service.qemu = MagicMock()
        threads_mock.deferToThread.return_value = Deferred()

        with patch("backend_pool.pool_service.CowrieConfig") as config_mock:
            config_mock.getint.return_value = -1
            service.start_pool()

        threads_mock.deferToThread.assert_called_once_with(service.producer_loop)
        reactor_mock.callLater.assert_not_called()
        self.assertIsNone(service.loop_next_call)
