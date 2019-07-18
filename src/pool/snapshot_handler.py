# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import shutil
import getpass
import subprocess


def create_disk_snapshot(source_img, destination_img):
    # snapshot_xml = util.read_file('../config_files/default_snapshot.xml')
    # s = domain.listAllSnapshots()
    # ret = domain.snapshotCreateXML(snapshot_xml, libvirt.VIR_DOMAIN_SNAPSHOT_CREATE_DISK_ONLY)

    try:
        shutil.chown(source_img, getpass.getuser())
    except PermissionError:
        pass
        # log.msg('Need root to create snapshot')

    out = subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-b', source_img, destination_img], capture_output=True)
    return out.returncode == 0
