# -*- test-case-name: cowrie.test.utils -*-
# Copyright (c) 2010-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import sys

from twisted.application import internet
from twisted.internet import endpoints, reactor


def durationHuman(seconds):
    """
    Turn number of seconds into human readable string
    """
    seconds = int(round(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    years, days = divmod(days, 365.242199)

    sdays = str(days)
    syears = str(years)
    sseconds = str(seconds).rjust(2, '0')
    sminutes = str(minutes).rjust(2, '0')
    shours = str(hours).rjust(2, '0')

    duration = []
    if years > 0:
        duration.append('{} year'.format(syears) + 's'*(years != 1) + ' ')
    else:
        if days > 0:
            duration.append('{} day'.format(days) + 's'*(days != 1) + ' ')
        if hours > 0:
            duration.append('{}:'.format(shours))
        if minutes >= 0:
            duration.append('{}:'.format(sminutes))
        if seconds >= 0:
            duration.append('{}'.format(sseconds))

    return ''.join(duration)



def tail(the_file, lines_2find=20):
    """
    From http://stackoverflow.com/questions/136168/get-last-n-lines-of-a-file-with-python-similar-to-tail
    """
    the_file.seek(0, 2)
    bytes_in_file = the_file.tell()
    lines_found, total_bytes_scanned = 0, 0
    while lines_2find+1 > lines_found and bytes_in_file > total_bytes_scanned:
        byte_block = min(1024, bytes_in_file-total_bytes_scanned)
        the_file.seek(-(byte_block+total_bytes_scanned), 2)
        total_bytes_scanned += byte_block
        lines_found += the_file.read(1024).count('\n')
    the_file.seek(-total_bytes_scanned, 2)
    line_list = list(the_file.readlines())
    return line_list[-lines_2find:]
    # We read at least 21 line breaks from the bottom, block by block for speed
    # 21 to ensure we don't get a half line



def uptime(total_seconds):
    """
    Gives a human-readable uptime string
    Thanks to http://thesmithfam.org/blog/2005/11/19/python-uptime-script/
    (modified to look like the real uptime command)
    """
    total_seconds = float(total_seconds)

    # Helper vars:
    MINUTE = 60
    HOUR = MINUTE * 60
    DAY = HOUR * 24

    # Get the days, hours, etc:
    days = int(total_seconds / DAY)
    hours = int((total_seconds % DAY) / HOUR)
    minutes = int((total_seconds % HOUR) / MINUTE)

    # 14 days,  3:53
    # 11 min

    s = ''
    if days > 0:
        s += str(days) + " " + (days == 1 and "day" or "days") + ", "
    if len(s) > 0 or hours > 0:
        s += '%s:%s' % (str(hours).rjust(2), str(minutes).rjust(2, '0'))
    else:
        s += '{} min'.format(str(minutes))
    return s


def get_endpoints_from_section(cfg, section, default_port):
    """
    """
    if cfg.has_option(section, 'listen_endpoints'):
        return cfg.get(section, 'listen_endpoints').split()

    if cfg.has_option(section, 'listen_addr'):
        listen_addr = cfg.get(section, 'listen_addr')
    else:
        listen_addr = '0.0.0.0'

    if cfg.has_option(section, 'listen_port'):
        listen_port = cfg.getint(section, 'listen_port')
    else:
        listen_port = default_port

    listen_endpoints = []
    for i in listen_addr.split():
        listen_endpoints.append('tcp:{}:interface={}'.format(listen_port, i))

    return listen_endpoints


def create_endpoint_services(reactor, parent, listen_endpoints, factory):
    """
    """
    for listen_endpoint in listen_endpoints:

        # work around http://twistedmatrix.com/trac/ticket/8422
        if sys.version_info.major < 3:
            endpoint = endpoints.serverFromString(reactor, listen_endpoint.encode('utf-8'))
        else:
            endpoint = endpoints.serverFromString(reactor, listen_endpoint)

        service = internet.StreamServerEndpointService(endpoint, factory)
        # FIXME: Use addService on parent ?
        service.setServiceParent(parent)
