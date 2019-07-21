# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information
import os

import backend_pool.util

import libvirt

from twisted.python import log

from cowrie.core.config import CowrieConfig


def create_filter(connection):
    filter_file = os.path.join(CowrieConfig().get('backend_pool', 'config_files_path', fallback='share/pool_configs'),
                               CowrieConfig().get('backend_pool', 'nw_filter_config', fallback='default_filter.xml'))

    filter_xml = backend_pool.util.read_file(filter_file)

    try:
        return connection.nwfilterDefineXML(filter_xml)
    except libvirt.libvirtError as e:
        log.err(eventid='cowrie.backend_pool.network_handler',
                format='Filter already exists: %(error)s',
                error=e)
        return connection.nwfilterLookupByName('cowrie-default-filter')


def create_network(connection):
    network_file = os.path.join(CowrieConfig().get('backend_pool', 'config_files_path', fallback='share/pool_configs'),
                                CowrieConfig().get('backend_pool', 'network_config', fallback='default_network.xml'))

    network_xml = backend_pool.util.read_file(network_file)

    sample_host = '<host mac=\'{mac_address}\' name=\'{name}\' ip=\'{ip_address}\'/>\n'
    hosts = ''

    for guest_id in range(2, 255):
        mac_address, ip_address = backend_pool.util.generate_mac_ip(guest_id)
        vm_name = 'vm' + str(guest_id)
        hosts += sample_host.format(mac_address=mac_address, name=vm_name, ip_address=ip_address)

    network_config = network_xml.format(network_name='cowrie',
                                        iface_name='virbr2',
                                        default_gateway='192.168.150.1',
                                        dhcp_range_start='192.168.150.2',
                                        dhcp_range_end='192.168.150.254',
                                        hosts=hosts)

    try:
        # create a transient virtual network
        net = connection.networkCreateXML(network_config)
        if net is None:
            log.msg(eventid='cowrie.backend_pool.network_handler',
                    format='Failed to define a virtual network')
            exit(1)

        # set the network active
        # not needed since apparently transient networks are created as active; uncomment if persistent
        # net.create()

        return net
    except libvirt.libvirtError as e:
        log.err(eventid='cowrie.backend_pool.network_handler',
                format='Network already exists: %(error)s',
                error=e)
        return connection.networkLookupByName('cowrie')
