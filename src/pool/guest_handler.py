# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information
from configparser import NoOptionError

import libvirt
import os

import pool.snapshot_handler
import pool.util

from cowrie.core.config import CowrieConfig

from twisted.python import log


class QemuGuestError(Exception):
    pass


def create_guest(connection, mac_address, guest_unique_id):
    # get guest configurations
    configuration_file = os.path.join(CowrieConfig().get('proxy', 'config_files_path', fallback='share/pool_configs'),
                                      CowrieConfig().get('proxy', 'guest_config', fallback='default_guest.xml'))
    version_tag = CowrieConfig().get('proxy', 'guest_tag', fallback='guest')
    base_image = CowrieConfig().get('proxy', 'base_image_path')

    # get a directory to save snapshots, even if temporary
    try:
        # guest configuration, to be read by qemu, needs an absolute path
        snapshot_path = pool.util.to_absolute_path(CowrieConfig().get('proxy', 'snapshot_path'))
    except NoOptionError:
        snapshot_path = os.getcwd()

    # create a disk snapshot to be used by the guest
    disk_img = os.path.join(snapshot_path, 'snapshot-{0}-{1}.qcow2'.format(version_tag, guest_unique_id))

    if not pool.snapshot_handler.create_disk_snapshot(base_image, disk_img):
        log.msg(eventid='cowrie.backend_pool.guest_handler',
                format='There was a problem creating the disk snapshot.')
        raise QemuGuestError()

    guest_xml = pool.util.read_file(configuration_file)
    guest_config = guest_xml.format(guest_name='cowrie-' + version_tag + '_' + guest_unique_id,
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
