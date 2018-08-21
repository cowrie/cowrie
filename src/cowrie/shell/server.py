from __future__ import absolute_import, division

import copy
import json
import random
from configparser import NoOptionError

import twisted.python.log as log

from cowrie.core.config import CONFIG
from cowrie.shell import fs


class CowrieServer(object):
    """
    In traditional Kippo each connection gets its own simulated machine.
    This is not always ideal, sometimes two connections come from the same
    source IP address. we want to give them the same environment as well.
    So files uploaded through SFTP are visible in the SSH session.
    This class represents a 'virtual server' that can be shared between
    multiple Cowrie connections
    """
    fs = None
    process = None
    avatars = []

    def __init__(self):
        self.hostname = CONFIG.get('honeypot', 'hostname')

        try:
            arches = [arch.strip() for arch in CONFIG.get('shell', 'arch').split(',')]
            self.arch = random.choice(arches)
        except NoOptionError:
            self.arch = 'linux-x64-lsb'

        log.msg("Initialized emulated server as architecture: {}".format(self.arch))

    def getCommandOutput(self, file):
        """
        Reads process output from JSON file.
        """
        with open(file) as f:
            cmdoutput = json.load(f)
        return cmdoutput

    def initFileSystem(self):
        """
        Do this so we can trigger it later. Not all sessions need file system
        """
        self.fs = fs.HoneyPotFilesystem(copy.deepcopy(fs.PICKLE), self.arch)

        try:
            self.process = self.getCommandOutput(CONFIG.get('shell', 'processes'))['command']['ps']
        except NoOptionError:
            self.process = None
