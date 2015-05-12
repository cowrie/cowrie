# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os
import ConfigParser

def config():
    cfg = ConfigParser.ConfigParser()
    for f in ('cowrie.cfg', '/etc/cowrie/cowrie.cfg', '/etc/cowrie.cfg'):
        if os.path.exists(f):
            cfg.read(f)
            return cfg
    return None

# vim: set sw=4 et:
