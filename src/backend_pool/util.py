# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import os
import random
import subprocess
import time


def ping(guest_ip):
    # could use `capture_output=True` instead of `stdout` and `stderr` args in Python 3.7
    out = subprocess.run(['ping', '-c 1', guest_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return out.returncode == 0


def nmap_port(guest_ip, port):
    # could use `capture_output=True` instead of `stdout` and `stderr` args in Python 3.7
    out = subprocess.run(['nmap', guest_ip, '-PN',  '-p', str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return out.returncode == 0 and b'open' in out.stdout


def read_file(file_name):
    with open(file_name, 'r') as file:
        return file.read()


def to_byte(n):
    return hex(n)[2:].zfill(2)


def generate_network_table(seed=None):
    """
    Generates a table associating MAC and IP addressed to be distributed by our virtual network adapter via DHCP.
    """

    # we use the seed in case we want to generate the same table twice
    if seed is not None:
        random.seed(seed)

    # number of IPs per network is 253 (2-254)
    # generate random MACs, set ensures they are unique
    macs = set()
    while len(macs) < 253:
        macs.add('48:d2:24:bf:' + to_byte(random.randint(0, 255)) + ':' + to_byte(random.randint(0, 255)))

    # associate each MAC with a sequential IP
    table = {}
    ip_counter = 2
    for mac in macs:
        table[mac] = '192.168.150.' + str(ip_counter)
        ip_counter += 1

    return table


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
