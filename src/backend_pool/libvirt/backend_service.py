# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information
import os
import uuid

import backend_pool.libvirt.guest_handler
import backend_pool.libvirt.network_handler
import backend_pool.util

import libvirt

from twisted.python import log

from cowrie.core.config import CowrieConfig


class LibvirtError(Exception):
    pass


class LibvirtBackendService:
    def __init__(self):
        # open connection to libvirt
        self.conn = libvirt.open('qemu:///system')
        if self.conn is None:
            log.msg(eventid='cowrie.backend_pool.qemu',
                    format='Failed to open connection to qemu:///system')
            raise LibvirtError()

        self.filter = None
        self.network = None

        # signals backend is ready to be operated
        self.ready = False

        log.msg(eventid='cowrie.backend_pool.qemu',
                format='Connection to Qemu established')

    def stop(self):
        log.msg(eventid='cowrie.backend_pool.qemu',
                format='Doing Qemu clean shutdown...')

        self.ready = False

        self.destroy_all_cowrie()

        self.conn.close()  # close libvirt connection

        log.msg(eventid='cowrie.backend_pool.qemu',
                format='Connection to Qemu closed successfully')

    def initialise_environment(self):
        """
        Initialises Qemu/libvirt environment needed to run guests. Namely starts networks and network filters.
        """
        # create a network filter
        self.filter = backend_pool.libvirt.network_handler.create_filter(self.conn)

        # create a NAT for the guests
        self.network = backend_pool.libvirt.network_handler.create_network(self.conn)

        self.ready = True

    def create_guest(self, guest_id):
        """
        Returns an unready domain and its snapshot information
        """
        if not self.ready:
            return

        # generate networking details
        guest_mac, guest_ip = backend_pool.util.generate_mac_ip(guest_id)
        guest_unique_id = uuid.uuid4().hex

        # create a single guest
        dom, snapshot = backend_pool.libvirt.guest_handler.create_guest(self.conn, guest_mac, guest_unique_id)
        if dom is None:
            log.msg(eventid='cowrie.backend_pool.qemu',
                    format='Failed to create guest')
            return None

        return dom, snapshot, guest_ip

    def destroy_guest(self, domain, snapshot):
        if not self.ready:
            return

        try:
            # destroy the domain in qemu
            domain.destroy()

            # we want to remove the snapshot if either:
            #   - explicitely set save_snapshots to False
            #   - no snapshot dir was defined (using cowrie's root dir) - should not happen but prevent it
            if not CowrieConfig().getboolean('proxy', 'save_snapshots', fallback=True) \
                    or CowrieConfig().get('proxy', 'snapshot_path', fallback=None) is None:
                os.remove(snapshot)  # destroy its disk snapshot
        except Exception as error:
            log.err(eventid='cowrie.backend_pool.qemu',
                    format='Error destroying guest: %(error)s',
                    error=error)

    def __destroy_all_guests(self):
        domains = self.conn.listDomainsID()
        if not domains:
            log.msg(eventid='cowrie.backend_pool.qemu',
                    format='Could not get domain list')

        for domain_id in domains:
            d = self.conn.lookupByID(domain_id)
            if d.name().startswith('cowrie'):
                try:
                    d.destroy()
                except KeyboardInterrupt:
                    pass

    def __destroy_all_networks(self):
        networks = self.conn.listNetworks()
        if not networks:
            log.msg(eventid='cowrie.backend_pool.qemu',
                    format='Could not get network list')

        for network in networks:
            if network.startswith('cowrie'):
                n = self.conn.networkLookupByName(network)
                n.destroy()

    def __destroy_all_network_filters(self):
        network_filters = self.conn.listNWFilters()
        if not network_filters:
            log.msg(eventid='cowrie.backend_pool.qemu',
                    format='Could not get network filters list')

        for nw_filter in network_filters:
            if nw_filter.startswith('cowrie'):
                n = self.conn.nwfilterLookupByName(nw_filter)
                n.undefine()

    def destroy_all_cowrie(self):
        self.__destroy_all_guests()
        self.__destroy_all_networks()
        self.__destroy_all_network_filters()
