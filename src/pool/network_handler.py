# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import sys
import libvirt

import pool.util

import os
def create_filter(connection):
    print(os.getcwd())
    filter_xml = pool.util.read_file('src/pool/config_files/default_filter.xml')

    try:
        return connection.nwfilterDefineXML(filter_xml)
    except libvirt.libvirtError as e:
        print(e)
        print('Filter already exists')
        return connection.nwfilterLookupByName('cowrie-default-filter')


def create_network(connection):
    print(os.getcwd())
    network_xml = pool.util.read_file('src/pool/config_files/default_network.xml')

    sample_host = '<host mac=\'{mac_address}\' name=\'{name}\' ip=\'{ip_address}\'/>\n'
    hosts = ''

    for guest_id in range(2, 255):
        mac_address, ip_address = pool.util.generate_mac_ip(guest_id)
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
            print('Failed to define a virtual network', file=sys.stderr)
            exit(1)

        # set the network active
        # not needed since apparently transient networks are created as active; uncomment if persistent
        # net.create()

        return net
    except libvirt.libvirtError as e:
        print(e)
        print('Network already exists')
        return connection.networkLookupByName('cowrie')