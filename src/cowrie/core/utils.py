# -*- test-case-name: cowrie.test.utils -*-
# Copyright (c) 2010-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from typing import BinaryIO, TYPE_CHECKING

from twisted.application import internet
from twisted.internet import endpoints

if TYPE_CHECKING:
    import configparser


def durationHuman(duration: float) -> str:
    """
    Turn number of seconds into human readable string
    """
    seconds: int = round(duration)
    minutes: int
    minutes, seconds = divmod(seconds, 60)
    hours: int
    hours, minutes = divmod(minutes, 60)
    days: float
    days, hours = divmod(hours, 24)
    years: float
    years, days = divmod(days, 365.242199)

    syears: str = str(years)
    sseconds: str = str(seconds).rjust(2, "0")
    sminutes: str = str(minutes).rjust(2, "0")
    shours: str = str(hours).rjust(2, "0")

    sduration: list[str] = []
    if years > 0:
        sduration.append("{} year{} ".format(syears, "s" * (years != 1)))
    else:
        if days > 0:
            sduration.append("{} day{} ".format(days, "s" * (days != 1)))
        if hours > 0:
            sduration.append(f"{shours}:")
        if minutes >= 0:
            sduration.append(f"{sminutes}:")
        if seconds >= 0:
            sduration.append(f"{sseconds}")

    return "".join(sduration)


def tail(the_file: BinaryIO, lines_2find: int = 20) -> list[bytes]:
    """
    From http://stackoverflow.com/questions/136168/get-last-n-lines-of-a-file-with-python-similar-to-tail
    """
    lines_found: int = 0
    total_bytes_scanned: int = 0

    the_file.seek(0, 2)
    bytes_in_file: int = the_file.tell()
    while lines_2find + 1 > lines_found and bytes_in_file > total_bytes_scanned:
        byte_block: int = min(1024, bytes_in_file - total_bytes_scanned)
        the_file.seek(-(byte_block + total_bytes_scanned), 2)
        total_bytes_scanned += byte_block
        lines_found += the_file.read(1024).count(b"\n")
    the_file.seek(-total_bytes_scanned, 2)
    line_list: list[bytes] = list(the_file.readlines())
    return line_list[-lines_2find:]
    # We read at least 21 line breaks from the bottom, block by block for speed
    # 21 to ensure we don't get a half line


def uptime(total_seconds: float) -> str:
    """
    Gives a human-readable uptime string
    Thanks to http://thesmithfam.org/blog/2005/11/19/python-uptime-script/
    (modified to look like the real uptime command)
    """
    total_seconds = float(total_seconds)

    # Helper vars:
    MINUTE: int = 60
    HOUR: int = MINUTE * 60
    DAY: int = HOUR * 24

    # Get the days, hours, etc:
    days: int = int(total_seconds / DAY)
    hours: int = int((total_seconds % DAY) / HOUR)
    minutes: int = int((total_seconds % HOUR) / MINUTE)

    # 14 days,  3:53
    # 11 min

    s: str = ""
    if days > 0:
        s += str(days) + " " + ((days == 1 and "day") or "days") + ", "
    if len(s) > 0 or hours > 0:
        s += "{}:{}".format(str(hours).rjust(2), str(minutes).rjust(2, "0"))
    else:
        s += f"{minutes!s} min"
    return s


def get_endpoints_from_section(
    cfg: configparser.ConfigParser, section: str, default_port: int
) -> list[str]:
    listen_addr: str
    listen_port: int
    listen_endpoints: list[str] = []

    if cfg.has_option(section, "listen_endpoints"):
        return cfg.get(section, "listen_endpoints").split()

    if cfg.has_option(section, "listen_addr"):
        listen_addr = cfg.get(section, "listen_addr")
    else:
        listen_addr = "0.0.0.0"

    if cfg.has_option(section, "listen_port"):
        listen_port = cfg.getint(section, "listen_port")
    else:
        listen_port = default_port

    for i in listen_addr.split():
        listen_endpoints.append(f"tcp:{listen_port}:interface={i}")

    return listen_endpoints


def create_endpoint_services(reactor, parent, listen_endpoints, factory):
    for listen_endpoint in listen_endpoints:
        endpoint = endpoints.serverFromString(reactor, listen_endpoint)

        service = internet.StreamServerEndpointService(endpoint, factory)
        # FIXME: Use addService on parent ?
        service.setServiceParent(parent)
