# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import libvirt

import pool.snapshot_handler
import pool.util

from twisted.python import log


class QemuGuestError(Exception):
    pass


def create_guest(connection, mac_address, guest_unique_id, snapshot_dir, configs):
    # create a disk snapshot to be used by the guest
    disk_img = snapshot_dir + 'snapshot-{0}-{1}.qcow2'.format(configs['version_tag'], guest_unique_id)

    if not pool.snapshot_handler.create_disk_snapshot(configs['base_image'], disk_img):
        log.msg(eventid='cowrie.backend_pool.guest_handler',
                format='There was a problem creating the disk snapshot.')
        raise QemuGuestError()

    guest_xml = pool.util.read_file(configs['config_file'])
    guest_config = guest_xml.format(guest_name='cowrie-' + configs['version_tag'] + '_' + guest_unique_id,
                                    disk_image=disk_img,
                                    mac_address=mac_address,
                                    network_name='cowrie')

    try:
        dom = connection.createXML(guest_config, 0)
        if dom is None:
            log.err(eventid='cowrie.backend_pool.guest_handler',
                    format='Failed to create a domain from an XML definition.')
            exit(1)

        log.msg(eventid='cowrie.backend_pool.guest_handler',
                format='Guest %(name)s has booted',
                name=dom.name())
        return dom, disk_img
    except libvirt.libvirtError as e:
        log.err(eventid='cowrie.backend_pool.guest_handler',
                format='Error booting guest: %(error)s',
                error=e)
        raise e
