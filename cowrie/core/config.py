# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import ConfigParser

def readConfigFile(cfgfile):
    cfg = ConfigParser.SafeConfigParser()
    cfg.readfp(open(cfgfile))
    return cfg

# vim: set sw=4 et:
