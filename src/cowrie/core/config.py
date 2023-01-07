# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains code to deal with Cowrie's configuration
"""

from __future__ import annotations

import configparser
from os import environ
from os.path import abspath, dirname, exists, join

from typing import Union


def to_environ_key(key: str) -> str:
    return key.upper()


class EnvironmentConfigParser(configparser.ConfigParser):
    """
    ConfigParser with additional option to read from environment variables
    # TODO: def sections()
    """

    def has_option(self, section: str, option: str) -> bool:
        if to_environ_key("_".join(("cowrie", section, option))) in environ:
            return True
        return super().has_option(section, option)

    def get(self, section: str, option: str, *, raw: bool = False, **kwargs) -> str:  # type: ignore
        key: str = to_environ_key("_".join(("cowrie", section, option)))
        if key in environ:
            return environ[key]
        return super().get(section, option, raw=raw, **kwargs)


def readConfigFile(cfgfile: Union[list[str], str]) -> configparser.ConfigParser:
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
    Get absolute path to the config file
    """
    current_path = abspath(dirname(__file__))
    root = "/".join(current_path.split("/")[:-3])

    config_files = [
        join(root, "etc/cowrie.cfg.dist"),
        "/etc/cowrie/cowrie.cfg",
        join(root, "etc/cowrie.cfg"),
        join(root, "cowrie.cfg"),
    ]
    found_confs = [path for path in config_files if exists(path)]

    if found_confs:
        return found_confs

    print("Config file not found")  # noqa: T201
    return []


CowrieConfig = readConfigFile(get_config_path())
