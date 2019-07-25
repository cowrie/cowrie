# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import os
import subprocess
import time


def ping(guest_ip):
    out = subprocess.run(['ping', '-c 1', guest_ip], capture_output=True)
    return out.returncode == 0


def nmap_port(guest_ip, port):
    out = subprocess.run(['nmap', guest_ip, '-PN',  '-p', str(port)], capture_output=True)
    return out.returncode == 0 and b'open' in out.stdout


def read_file(file_name):
    with open(file_name, 'r') as file:
        return file.read()


def generate_mac_ip(guest_id):
    # TODO support more
    hex_id = hex(guest_id)[2:]
    mac = 'aa:bb:cc:dd:ee:' + hex_id.zfill(2)
    ip = '192.168.150.' + str(guest_id)
    return mac, ip


def now():
    return time.time()


def to_absolute_path(path):
    """
    Converts a relative path to absolute, useful when converting cowrie configs (relative) to qemu paths
    (which must be absolute)
    """
    if not os.path.isabs(path):
        return os.path.join(os.getcwd(), path)
    else:
        return path
