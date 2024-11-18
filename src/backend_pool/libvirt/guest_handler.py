# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information
from __future__ import annotations
import os
import sys
from configparser import NoOptionError

from twisted.python import log

from cowrie.core.config import CowrieConfig

import backend_pool.libvirt.snapshot_handler
import backend_pool.util


class QemuGuestError(Exception):
    pass


def create_guest(connection, mac_address, guest_unique_id):
    # lazy import to avoid exception if not using the backend_pool and libvirt not installed (#1185)
    import libvirt

    # get guest configurations
    configuration_file: str = os.path.join(
        CowrieConfig.get(
            "backend_pool", "config_files_path", fallback="src/cowrie/data/pool_configs"
        ),
        CowrieConfig.get("backend_pool", "guest_config", fallback="default_guest.xml"),
    )

    version_tag: str = CowrieConfig.get("backend_pool", "guest_tag", fallback="guest")
    base_image: str = CowrieConfig.get("backend_pool", "guest_image_path")
    hypervisor: str = CowrieConfig.get(
        "backend_pool", "guest_hypervisor", fallback="qemu"
    )
    memory: int = CowrieConfig.getint("backend_pool", "guest_memory", fallback=128)
    qemu_machine: str = CowrieConfig.get(
        "backend_pool", "guest_qemu_machine", fallback="pc-q35-3.1"
    )

    # check if base image exists
    if not os.path.isfile(base_image):
        log.msg(
            eventid="cowrie.backend_pool.guest_handler",
            format="Base image provided was not found: %(base_image)s",
            base_image=base_image,
        )
        os._exit(1)

    # only in some cases, like wrt
    kernel_image: str = CowrieConfig.get(
        "backend_pool", "guest_kernel_image", fallback=""
    )

    # get a directory to save snapshots, even if temporary
    try:
        # guest configuration, to be read by qemu, needs an absolute path
        snapshot_path: str = backend_pool.util.to_absolute_path(
            CowrieConfig.get("backend_pool", "snapshot_path")
        )
    except NoOptionError:
        snapshot_path = os.getcwd()

    # create a disk snapshot to be used by the guest
    disk_img: str = os.path.join(
        snapshot_path, f"snapshot-{version_tag}-{guest_unique_id}.qcow2"
    )

    if not backend_pool.libvirt.snapshot_handler.create_disk_snapshot(
        base_image, disk_img
    ):
        log.msg(
            eventid="cowrie.backend_pool.guest_handler",
            format="There was a problem creating the disk snapshot.",
        )
        raise QemuGuestError()

    guest_xml = backend_pool.util.read_file(configuration_file)
    guest_config = guest_xml.format(
        guest_name="cowrie-" + version_tag + "_" + guest_unique_id,
        disk_image=disk_img,
        base_image=base_image,
        kernel_image=kernel_image,
        hypervisor=hypervisor,
        memory=memory,
        qemu_machine=qemu_machine,
        mac_address=mac_address,
        network_name="cowrie",
    )

    try:
        dom = connection.createXML(guest_config, 0)
        if dom is None:
            log.err(
                eventid="cowrie.backend_pool.guest_handler",
                format="Failed to create a domain from an XML definition.",
            )
            sys.exit(1)
    except libvirt.libvirtError as e:
        log.err(
            eventid="cowrie.backend_pool.guest_handler",
            format="Error booting guest: %(error)s",
            error=e,
        )
        raise
    log.msg(
        eventid="cowrie.backend_pool.guest_handler",
        format="Guest %(name)s has booted",
        name=dom.name(),
    )
    return dom, disk_img
