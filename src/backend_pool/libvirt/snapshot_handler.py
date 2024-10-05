# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from contextlib import suppress
import getpass
import shutil
import subprocess


def create_disk_snapshot(source_img: str, destination_img: str) -> bool:
    with suppress(PermissionError):
        shutil.chown(source_img, getpass.getuser())

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
