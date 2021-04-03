# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains code to deal with Cowrie's configuration
"""


import configparser
from os import environ
from os.path import abspath, dirname, exists, join


def to_environ_key(key):
    return key.upper()


class EnvironmentConfigParser(configparser.ConfigParser):
    """
    ConfigParser with additional option to read from environment variables
    # TODO: def sections()
    """

    def has_option(self, section, option):
        if to_environ_key("_".join(("cowrie", section, option))) in environ:
            return True
        return super().has_option(section, option)

    def get(self, section, option, raw=False, **kwargs):
        key = to_environ_key("_".join(("cowrie", section, option)))
        if key in environ:
            return environ[key]
        return super().get(section, option, raw=raw, **kwargs)


def readConfigFile(cfgfile):
    """
    Read config files and return ConfigParser object

    @param cfgfile: filename or array of filenames
    @return: ConfigParser object
    """
    parser = EnvironmentConfigParser(interpolation=configparser.ExtendedInterpolation())
    parser.read(cfgfile)
    return parser


def get_config_path():
    """Get absolute path to the config file"""
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

    print("Config file not found")


CowrieConfig = readConfigFile(get_config_path())
