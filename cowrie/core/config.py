# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import configparser
import os


def to_environ_key(key):
    return key.upper()


class EnvironmentConfigParser(configparser.ConfigParser):

    def has_option(self, section, option):
        if to_environ_key('_'.join((section, option))) in os.environ:
            return True
        return super(EnvironmentConfigParser, self).has_option(section, option)

    def get(self, section, option, **kwargs):
        key = to_environ_key('_'.join((section, option)))
        if key in os.environ:
            return os.environ[key]
        return super(EnvironmentConfigParser, self).get(section, option, **kwargs)


def readConfigFile(cfgfile):
    """
    Read config files and return ConfigParser object

    @param cfgfile: filename or array of filenames
    @return: ConfigParser object
    """
    parser = EnvironmentConfigParser()
    parser.read(cfgfile)
    return parser

CONFIG = readConfigFile(("cowrie.cfg.dist", "etc/cowrie.cfg", "cowrie.cfg"))
