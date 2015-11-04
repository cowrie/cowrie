# Copyright (c) Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

import copy

from . import fs
from . import honeypot

class CowrieServer:
    """
    In traditional Kippo each connect gets its own simulated machine.
    This is not always ideal, sometimes two connections come from the same
    source IP address. we want to give them the same environment as well.
    So files uploaded through SFTP are visible in the SSH session.
    This class represents a 'virtual server' that can be shared between
    multiple Cowrie connections
    """
    def __init__(self, cfg):
	self.cfg = cfg
        self.env = honeypot.HoneyPotEnvironment(cfg)
        self.fs = fs.HoneyPotFilesystem(copy.deepcopy(self.env.fs),self.env.cfg)

