# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import configparser

def readConfigFile(cfgfile):
    config = configparser.ConfigParser()
    config.read(cfgfile)
    return config

