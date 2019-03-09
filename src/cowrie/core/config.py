# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import absolute_import, division

import configparser
from os import environ
from os.path import abspath, dirname, exists, join


def to_environ_key(key):
    return key.upper()


class EnvironmentConfigParser(configparser.ConfigParser):

    def has_option(self, section, option):
        if to_environ_key('_'.join((section, option))) in environ:
            return True
        return super(EnvironmentConfigParser, self).has_option(section, option)

    def get(self, section, option, **kwargs):
        key = to_environ_key('_'.join((section, option)))
        if key in environ:
            return environ[key]
        return super(EnvironmentConfigParser, self).get(
            section, option, **kwargs)


def readConfigFile(cfgfile):
    """
    Read config files and return ConfigParser object

    @param cfgfile: filename or array of filenames
    @return: ConfigParser object
    """
    parser = EnvironmentConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    parser.read(cfgfile)
    return parser


def get_config_path():
    """Get absolute path to the config file
    """
    config_files = ["etc/cowrie.cfg.dist", "etc/cowrie/cowrie.cfg",
                    "etc/cowrie.cfg", "cowrie.cfg"]
    current_path = abspath(dirname(__file__))
    root = "/".join(current_path.split("/")[:-3])

    conf_abs_paths = (join(root, file) for file in config_files)
    found_confs = [path for path in conf_abs_paths if exists(path)]

    if found_confs:
        return found_confs

    print("Config file not found")


CONFIG = readConfigFile(get_config_path())
