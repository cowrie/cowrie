# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import getpass
import shutil
import subprocess


def create_disk_snapshot(source_img, destination_img):
    try:
        shutil.chown(source_img, getpass.getuser())
    except PermissionError:
        # log.msg('Should have root to create snapshot')
        pass

    # could use `capture_output=True` instead of `stdout` and `stderr` args in Python 3.7
    out = subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            source_img,
            destination_img,
        ],
        capture_output=True,
    )
    return out.returncode == 0
