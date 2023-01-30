# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import annotations

import time

from twisted.cred import portal as tp
from twisted.internet import protocol
from twisted.plugin import IPlugin
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.telnet.transport import CowrieTelnetTransport
from cowrie.telnet.userauth import HoneyPotTelnetAuthProtocol
from cowrie.telnet_proxy.server_transport import FrontendTelnetTransport


class HoneyPotTelnetFactory(protocol.ServerFactory):
    """
    This factory creates HoneyPotTelnetAuthProtocol instances
    They listen directly to the TCP port
    """

    tac: IPlugin
    portal: tp.Portal | None = None  # gets set by Twisted plugin
    banner: bytes
    starttime: float

    def __init__(self, backend, pool_handler):
        self.backend: str = backend
        self.pool_handler = pool_handler
        super().__init__()

    # TODO logging clarity can be improved: see what SSH does
    def logDispatch(self, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        args["sessionno"] = "T{}".format(str(args["sessionno"]))
        for output in self.tac.output_plugins:
            output.logDispatch(**args)

    def startFactory(self):
        try:
            honeyfs = CowrieConfig.get("honeypot", "contents_path")
            issuefile = honeyfs + "/etc/issue.net"
            with open(issuefile, "rb") as banner:
                self.banner = banner.read()
        except OSError:
            self.banner = b""

        # For use by the uptime command
        self.starttime = time.time()

        # hook protocol
        if self.backend == "proxy":
            self.protocol = lambda: FrontendTelnetTransport()
        else:
            self.protocol = lambda: CowrieTelnetTransport(
                HoneyPotTelnetAuthProtocol, self.portal
            )

        protocol.ServerFactory.startFactory(self)
        log.msg("Ready to accept Telnet connections")

    def stopFactory(self) -> None:
        """
        Stop output plugins
        """
        protocol.ServerFactory.stopFactory(self)

    def buildProtocol(self, addr):
        """
        Overidden so we can keep a reference to running protocols (which is used for testing)
        """
        p = self.protocol()
        p.factory = self

        return p
