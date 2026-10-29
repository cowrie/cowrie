# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that a guest which fails to boot reports failure instead of
# ABOUTME: exiting the whole process (issue #40451).

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from typing import Any
from unittest import mock

from backend_pool.libvirt import backend_service, guest_handler
from cowrie.test.configoverride import override_option


class CreateGuestTests(unittest.TestCase):
    """create_guest reports a domain that failed to boot."""

    def setUp(self) -> None:
        # A base image that exists, a writable snapshot directory.
        fd, self.base_image = tempfile.mkstemp(suffix=".qcow2")
        os.close(fd)
        self.addCleanup(os.unlink, self.base_image)
        override_option(self, "backend_pool", "guest_image_path", self.base_image)
        self.snapshot_path = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.snapshot_path, ignore_errors=True)
        override_option(self, "backend_pool", "snapshot_path", self.snapshot_path)

        # libvirt is not installed in the test environment; create_guest
        # imports it lazily.
        libvirt: Any = mock.MagicMock()
        libvirt.libvirtError = type("libvirtError", (Exception,), {})
        modules = mock.patch.dict(sys.modules, {"libvirt": libvirt})
        modules.start()
        self.addCleanup(modules.stop)

        # The snapshot step drives qemu-img, which is not under test here.
        snapshot = mock.patch(
            "backend_pool.libvirt.snapshot_handler.create_disk_snapshot",
            return_value=True,
        )
        snapshot.start()
        self.addCleanup(snapshot.stop)

    def test_failed_domain_creation_returns_none(self) -> None:
        # libvirt returns None when the XML cannot be instantiated: the
        # guest attempt must fail without taking the process with it
        # (issue #40451).
        connection: Any = mock.MagicMock()
        connection.createXML.return_value = None

        self.assertIsNone(
            guest_handler.create_guest(connection, "52:54:00:11:22:33", "c0ffee0000")
        )

    def test_booted_domain_is_returned_with_snapshot(self) -> None:
        connection: Any = mock.MagicMock()
        domain: Any = mock.MagicMock()
        domain.name = mock.Mock(return_value="cowrie-guest-test")
        connection.createXML.return_value = domain

        result = guest_handler.create_guest(
            connection, "52:54:00:11:22:33", "c0ffee0000"
        )

        assert result is not None
        self.assertIs(result[0], domain)
        self.assertTrue(result[1].endswith(".qcow2"))


class BackendServiceCreateGuestTests(unittest.TestCase):
    """LibvirtBackendService.create_guest translates a failed boot to None."""

    def setUp(self) -> None:
        # libvirt is not installed in the test environment; both the
        # service constructor and the handler import it lazily.
        libvirt: Any = mock.MagicMock()
        libvirt.libvirtError = type("libvirtError", (Exception,), {})
        libvirt.open.return_value = mock.MagicMock()
        modules = mock.patch.dict(sys.modules, {"libvirt": libvirt})
        modules.start()
        self.addCleanup(modules.stop)

    def test_failed_boot_returns_none(self) -> None:
        service = backend_service.LibvirtBackendService()
        service.ready = True

        handler = mock.patch(
            "backend_pool.libvirt.guest_handler.create_guest",
            return_value=None,
        )
        handler.start()
        self.addCleanup(handler.stop)

        self.assertIsNone(service.create_guest(lambda ip: True))

    def test_booted_guest_is_returned_with_snapshot(self) -> None:
        service = backend_service.LibvirtBackendService()
        service.ready = True
        domain: Any = mock.MagicMock()

        handler = mock.patch(
            "backend_pool.libvirt.guest_handler.create_guest",
            return_value=(domain, "/tmp/snapshot-guest-x.qcow2"),
        )
        handler.start()
        self.addCleanup(handler.stop)

        result = service.create_guest(lambda ip: True)

        assert result is not None
        dom, snapshot, ip = result
        self.assertIs(dom, domain)
        self.assertEqual(snapshot, "/tmp/snapshot-guest-x.qcow2")
        self.assertIn(ip, service.network_table.values())
