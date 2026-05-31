# SPDX-FileCopyrightText: 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# SPDX-FileCopyrightText: 2015, 2016 GoSecure Inc.
# SPDX-FileCopyrightText: 2019-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from twisted.internet import protocol
from twisted.python import log

from cowrie.shell.honeyfs import read_honeyfs_bytes
from cowrie.telnet.transport import CowrieTelnetTransport
from cowrie.telnet.userauth import HoneyPotTelnetAuthProtocol
from cowrie.telnet_proxy.server_transport import FrontendTelnetTransport

if TYPE_CHECKING:
    from twisted.cred import portal as tp
    from twisted.plugin import IPlugin


class HoneyPotTelnetFactory(protocol.ServerFactory):
    """
    This factory creates HoneyPotTelnetAuthProtocol instances
    They listen directly to the TCP port
    """

    tac: IPlugin
    banner: bytes
    starttime: float

    def __init__(self, backend, pool_handler):
        self.portal: tp.Portal | None = None  # gets set by Twisted plugin
        self.backend: str = backend
        self.pool_handler = pool_handler
        super().__init__()

    # TODO logging clarity can be improved: see what SSH does
    def logDispatch(self, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        args["sessionno"] = f"T{args['sessionno']}"
        for output in self.tac.output_plugins:
            output.logDispatch(**args)

    def startFactory(self) -> None:
        """ """
        try:
            self.banner = (
                read_honeyfs_bytes("etc/issue.net")
                .decode("utf-8", errors="replace")
                .encode("utf-8")
            )
        except FileNotFoundError as e:
            log.err(e, "ERROR: Failed to load /etc/issue.net")
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

        super().startFactory()
        log.msg("Ready to accept Telnet connections")

    def stopFactory(self) -> None:
        """
        Stop output plugins
        """
        super().stopFactory()
