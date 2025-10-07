"""
backend service
"""

# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import os
import random
import sys
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

from twisted.python import log

from cowrie.core.config import CowrieConfig

import backend_pool.libvirt.guest_handler
import backend_pool.libvirt.network_handler
import backend_pool.util


class LibvirtError(Exception):
    pass


class LibvirtBackendService:
    def __init__(self) -> None:
        # lazy import to avoid exception if not using the backend_pool
        # and libvirt not installed (#1185)
        import libvirt

        libvirt_uri: str = CowrieConfig.get(
            "backend_pool", "libvirt_uri", fallback="qemu:///system"
        )

        # open connection to libvirt
        self.conn = libvirt.open(libvirt_uri)
        if self.conn is None:
            log.msg(
                eventid="cowrie.backend_pool.libvirtd",
                format="Failed to open connection to libvirtd at %(uri)s",
                uri=libvirt_uri,
            )
            raise LibvirtError()

        self.filter = None
        self.network = None

        # signals backend is ready to be operated
        self.ready: bool = False

        # table to associate IPs and MACs
        seed: int = random.randint(0, sys.maxsize)
        self.network_table = backend_pool.util.generate_network_table(seed)

        log.msg(
            eventid="cowrie.backend_pool.libvirtd",
            format="Connection to libvirtd established at %(uri)s",
            uri=libvirt_uri,
        )

    def start_backend(self) -> None:
        """
        Initialises QEMU/libvirt environment needed to run guests.
        Namely starts networks and network filters.
        """
        # create a network filter
        self.filter = backend_pool.libvirt.network_handler.create_filter(self.conn)

        # create a network for the guests (as a NAT)
        self.network = backend_pool.libvirt.network_handler.create_network(
            self.conn, self.network_table
        )

        # service is ready to be used (create guests and use them)
        self.ready = True

    def stop_backend(self) -> None:
        log.msg(
            eventid="cowrie.backend_pool.libvirtd",
            format="Doing libvirtd clean shutdown...",
        )

        self.ready = False

        self.destroy_all_cowrie()

    def shutdown_backend(self) -> None:
        self.conn.close()  # close libvirt connection

        log.msg(
            eventid="cowrie.backend_pool.libvirtd",
            format="Connection to libvirtd closed successfully",
        )

    def get_mac_ip(self, ip_tester: Callable[[str], bool]) -> tuple[str, str]:
        """
        Get a MAC and IP that are not being used by any guest.
        """
        # Try to find a free pair 500 times.
        retries = 0
        while retries < 500:
            mac = random.choice(list(self.network_table.keys()))
            ip = self.network_table[mac]
            if ip_tester(ip):
                return mac, ip

            retries += 1

        raise LibvirtError()

    def create_guest(self, ip_tester):
        """
        Returns an unready domain and its snapshot information.

        Guarantee that the IP is free with the ip_tester function.
        """
        if not self.ready:
            return

        # create a single guest
        guest_unique_id = uuid.uuid4().hex
        guest_mac, guest_ip = self.get_mac_ip(ip_tester)
        dom, snapshot = backend_pool.libvirt.guest_handler.create_guest(
            self.conn, guest_mac, guest_unique_id
        )
        if dom is None:
            log.msg(
                eventid="cowrie.backend_pool.libvirtd", format="Failed to create guest"
            )
            return None

        return dom, snapshot, guest_ip

    def destroy_guest(self, domain, snapshot):
        if not self.ready:
            return

        try:
            # destroy the domain in QEMU
            domain.destroy()

            # we want to remove the snapshot if either:
            #   - explicitely set save_snapshots to False
            #   - no snapshot dir was defined (using cowrie's root dir) - should not happen but prevent it
            if (
                (
                    not CowrieConfig.getboolean(
                        "backend_pool", "save_snapshots", fallback=True
                    )
                    or CowrieConfig.get("backend_pool", "snapshot_path", fallback=None)
                    is None
                )
                and os.path.exists(snapshot)
                and os.path.isfile(snapshot)
            ):
                os.remove(snapshot)  # destroy its disk snapshot
        except Exception as error:
            log.err(
                eventid="cowrie.backend_pool.libvirtd",
                format="Error destroying guest: %(error)s",
                error=error,
            )

    def __destroy_all_guests(self) -> None:
        domains = self.conn.listDomainsID()
        # if not domains:
        #     log.msg(
        #         eventid="cowrie.backend_pool.libvirtd",
        #         format="Could not get domain list",
        #     )

        for domain_id in domains:
            d = self.conn.lookupByID(domain_id)
            if d.name().startswith("cowrie"):
                try:
                    d.destroy()
                except KeyboardInterrupt:
                    pass

    def __destroy_all_networks(self) -> None:
        networks = self.conn.listNetworks()
        # if not networks:
        #     log.msg(
        #         eventid="cowrie.backend_pool.libvirtd",
        #         format="Could not get network list",
        #     )

        for network in networks:
            if network.startswith("cowrie"):
                n = self.conn.networkLookupByName(network)
                n.destroy()

    def __destroy_all_network_filters(self) -> None:
        network_filters = self.conn.listNWFilters()
        # if not network_filters:
        #     log.msg(
        #         eventid="cowrie.backend_pool.libvirtd",
        #         format="Could not get network filters list",
        #     )

        for nw_filter in network_filters:
            if nw_filter.startswith("cowrie"):
                n = self.conn.nwfilterLookupByName(nw_filter)
                n.undefine()

    def destroy_all_cowrie(self) -> None:
        self.__destroy_all_guests()
        self.__destroy_all_networks()
        self.__destroy_all_network_filters()
