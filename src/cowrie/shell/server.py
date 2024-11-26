# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


from __future__ import annotations

import json
import random
from configparser import NoOptionError

from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from twisted.cred.portal import IRealm


class CowrieServer:
    """
    In traditional Kippo each connection gets its own simulated machine.
    This is not always ideal, sometimes two connections come from the same
    source IP address. we want to give them the same environment as well.
    So files uploaded through SFTP are visible in the SSH session.
    This class represents a 'virtual server' that can be shared between
    multiple Cowrie connections
    """

    def __init__(self, realm: IRealm) -> None:
        self.fs = None
        self.process = None
        self.hostname: str = CowrieConfig.get("honeypot", "hostname", fallback="svr04")
        try:
            arches = [
                arch.strip()
                for arch in CowrieConfig.get(
                    "shell", "arch", fallback="linux-x64-lsb"
                ).split(",")
            ]
            self.arch = random.choice(arches)
        except NoOptionError:
            self.arch = "linux-x64-lsb"

        log.msg(f"Initialized emulated server as architecture: {self.arch}")

    def getCommandOutput(self, file):
        """
        Reads process output from JSON file.
        """
        with open(file, encoding="utf-8") as f:
            cmdoutput = json.load(f)
        return cmdoutput

    def initFileSystem(self, home):
        """
        Do this so we can trigger it later. Not all sessions need file system
        """
        self.fs = fs.HoneyPotFilesystem(self.arch, home)

        try:
            self.process = self.getCommandOutput(
                CowrieConfig.get("shell", "processes")
            )["command"]["ps"]
        except NoOptionError:
            self.process = None
