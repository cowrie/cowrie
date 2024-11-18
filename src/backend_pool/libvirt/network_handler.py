# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information
from __future__ import annotations
import os
import sys

from twisted.python import log

from cowrie.core.config import CowrieConfig

import backend_pool.util


def create_filter(connection):
    # lazy import to avoid exception if not using the backend_pool and libvirt not installed (#1185)
    import libvirt

    filter_file: str = os.path.join(
        CowrieConfig.get(
            "backend_pool", "config_files_path", fallback="src/cowrie/data/pool_configs"
        ),
        CowrieConfig.get(
            "backend_pool", "nw_filter_config", fallback="default_filter.xml"
        ),
    )

    filter_xml = backend_pool.util.read_file(filter_file)

    try:
        return connection.nwfilterDefineXML(filter_xml)
    except libvirt.libvirtError as e:
        log.err(
            eventid="cowrie.backend_pool.network_handler",
            format="Filter already exists: %(error)s",
            error=e,
        )
        return connection.nwfilterLookupByName("cowrie-default-filter")


def create_network(connection, network_table):
    # lazy import to avoid exception if not using the backend_pool and libvirt not installed (#1185)
    import libvirt

    # TODO support more interfaces and therefore more IP space to allow > 253 guests
    network_file: str = os.path.join(
        CowrieConfig.get(
            "backend_pool", "config_files_path", fallback="src/cowrie/data/pool_configs"
        ),
        CowrieConfig.get(
            "backend_pool", "network_config", fallback="default_network.xml"
        ),
    )

    network_xml = backend_pool.util.read_file(network_file)

    template_host: str = "<host mac='{mac_address}' name='{name}' ip='{ip_address}'/>\n"
    hosts: str = ""

    # generate a host entry for every possible guest in this network (253 entries)
    it = iter(network_table)
    for guest_id in range(0, 253):
        vm_name = "vm" + str(guest_id)

        key = next(it)
        hosts += template_host.format(
            name=vm_name, mac_address=key, ip_address=network_table[key]
        )

    network_config = network_xml.format(
        network_name="cowrie",
        iface_name="virbr2",
        default_gateway="192.168.150.1",
        dhcp_range_start="192.168.150.2",
        dhcp_range_end="192.168.150.254",
        hosts=hosts,
    )

    # create a transient virtual network
    try:
        net = connection.networkCreateXML(network_config)
        if net is None:
            log.msg(
                eventid="cowrie.backend_pool.network_handler",
                format="Failed to define a virtual network",
            )
            sys.exit(1)

        # set the network active
        # not needed since apparently transient networks are created as active; uncomment if persistent
        # net.create()

    except libvirt.libvirtError as e:
        log.err(
            eventid="cowrie.backend_pool.network_handler",
            format="Network already exists: %(error)s",
            error=e,
        )
        return connection.networkLookupByName("cowrie")

    return net
