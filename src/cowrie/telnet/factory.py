# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import absolute_import, division

import time


from twisted.internet import protocol
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.telnet.transport import CowrieTelnetTransport
from cowrie.telnet.userauth import HoneyPotTelnetAuthProtocol
from cowrie.telnet_proxy.server_transport import FrontendTelnetTransport


# object is added for Python 2.7 compatibility (#1198) - as is super with args
class HoneyPotTelnetFactory(protocol.ServerFactory, object):
    """
    This factory creates HoneyPotTelnetAuthProtocol instances
    They listen directly to the TCP port
    """
    tac = None

    def __init__(self, backend, pool_handler):
        self.backend = backend
        self.pool_handler = pool_handler
        super(HoneyPotTelnetFactory, self).__init__()

    # TODO logging clarity can be improved: see what SSH does
    def logDispatch(self, *msg, **args):
        """
        Special delivery to the loggers to avoid scope problems
        """
        args['sessionno'] = 'T{0}'.format(str(args['sessionno']))
        for output in self.tac.output_plugins:
            output.logDispatch(*msg, **args)

    def startFactory(self):
        try:
            honeyfs = CowrieConfig().get('honeypot', 'contents_path')
            issuefile = honeyfs + "/etc/issue.net"
            self.banner = open(issuefile, 'rb').read()
        except IOError:
            self.banner = b""

        # For use by the uptime command
        self.starttime = time.time()

        # hook protocol
        if self.backend == 'proxy':
            self.protocol = lambda: FrontendTelnetTransport()
        else:
            self.protocol = lambda: CowrieTelnetTransport(HoneyPotTelnetAuthProtocol, self.portal)

        protocol.ServerFactory.startFactory(self)
        log.msg("Ready to accept Telnet connections")

    def stopFactory(self):
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
