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

from cowrie.core.resources import read_data_bytes


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
    Build a ConfigParser by stacking layers:

      1. Bundled cowrie.cfg.dist from the package (default values).
      2. The user files listed in cfgfile (overlays; last wins per key).

    @param cfgfile: filename or list of filenames for operator overlays
    @return: ConfigParser object
    """
    parser = EnvironmentConfigParser(interpolation=configparser.ExtendedInterpolation())
    try:
        parser.read_string(
            read_data_bytes("etc", "cowrie.cfg.dist").decode("utf-8")
        )
    except FileNotFoundError:
        log.msg("Bundled cowrie.cfg.dist not found in cowrie.data")
    parser.read(cfgfile)
    return parser


def get_config_path() -> list[str]:
    """
    Locate operator config files. Search order, cwd-relative except the
    system-wide path:

      1. /etc/cowrie/cowrie.cfg (system-wide install)
      2. ./etc/cowrie.cfg       (operator overrides)
      3. ./cowrie.cfg           (operator overrides, flat layout)

    Bundled defaults are loaded separately in readConfigFile; this
    function only returns operator-owned files. Last file wins per key.
    """
    config_files = [
        "/etc/cowrie/cowrie.cfg",
        "etc/cowrie.cfg",
        "cowrie.cfg",
    ]
    found_confs = [path for path in config_files if exists(path)]

    if found_confs:
        log.msg(f"Reading configuration from {found_confs!r}")
    else:
        log.msg("No operator config file found; using bundled defaults only")
    return found_confs


CowrieConfig = readConfigFile(get_config_path())
