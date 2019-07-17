# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import sys
import libvirt

import pool.snapshot_handler
import pool.util


class QemuGuestError(Exception):
    pass


def create_guest(connection, mac_address, guest_unique_id, snapshot_dir, configs):
    # create a disk snapshot to be used by the guest
    disk_img = snapshot_dir + 'snapshot-{0}-{1}.qcow2'.format(configs['version_tag'], guest_unique_id)

    if not pool.snapshot_handler.create_disk_snapshot(configs['base_image'], disk_img):
        print('There was a problem creating the disk snapshot.', file=sys.stderr)
        raise QemuGuestError()

    guest_xml = pool.util.read_file(configs['config_file'])
    guest_config = guest_xml.format(guest_name='cowrie-' + configs['version_tag'] + '_' + guest_unique_id,
                                    disk_image=disk_img,
                                    mac_address=mac_address,
                                    network_name='cowrie')

    try:
        dom = connection.createXML(guest_config, 0)
        if dom is None:
            print('Failed to create a domain from an XML definition.', file=sys.stderr)
            exit(1)

        print('Guest ' + dom.name() + ' has booted', file=sys.stderr)
        return dom, disk_img
    except libvirt.libvirtError as e:
        print('Error booting guest: {0}'.format(e))
        raise e
