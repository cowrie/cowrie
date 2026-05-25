# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
This module contains code to deal with Cowrie's configuration
"""

from __future__ import annotations

import configparser
from os import environ
from os.path import exists

from twisted.python import log


def to_environ_key(key: str) -> str:
    return key.upper()


class EnvironmentConfigParser(configparser.ConfigParser):
    """
    ConfigParser with additional option to read from environment variables
    # TODO: def sections()
    """

    # Python 3.14+ changed the signature to accept str | _UNNAMED_SECTION
    def has_option(  # type: ignore[override,unused-ignore]
        self, section: str, option: str
    ) -> bool:
        if to_environ_key("_".join(("cowrie", section, option))) in environ:
            return True
        return super().has_option(section, option)

    def get(self, section: str, option: str, *, raw: bool = False, **kwargs) -> str:  # type: ignore
        key: str = to_environ_key("_".join(("cowrie", section, option)))
        if key in environ:
            return environ[key]
        return super().get(section, option, raw=raw, **kwargs)


def readConfigFile(cfgfile: list[str] | str) -> configparser.ConfigParser:
    """
    Read config files and return ConfigParser object

    @param cfgfile: filename or list of filenames
    @return: ConfigParser object
    """
    parser = EnvironmentConfigParser(interpolation=configparser.ExtendedInterpolation())
    parser.read(cfgfile)
    return parser


def get_config_path() -> list[str]:
    """
    Locate cowrie configuration files. Search order, cwd-relative except
    the system-wide path:

      1. ./etc/cowrie.cfg.dist  (source-checkout defaults)
      2. /etc/cowrie/cowrie.cfg (system-wide install)
      3. ./etc/cowrie.cfg       (operator overrides)
      4. ./cowrie.cfg           (operator overrides, flat layout)

    Returns the absolute paths of all files that exist, in the order
    configparser should read them (later files override earlier ones).
    """
    config_files = [
        "etc/cowrie.cfg.dist",
        "/etc/cowrie/cowrie.cfg",
        "etc/cowrie.cfg",
        "cowrie.cfg",
    ]
    found_confs = [path for path in config_files if exists(path)]

    if found_confs:
        log.msg(f"Reading configuration from {found_confs!r}")
        return found_confs

    log.msg("Config file not found")
    return []


CowrieConfig = readConfigFile(get_config_path())
