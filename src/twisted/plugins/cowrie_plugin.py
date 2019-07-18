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

from __future__ import absolute_import, division, print_function

import os
import sys

from twisted._version import __version__
from twisted.application import service, internet
from twisted.application.service import IServiceMaker
from twisted.cred import portal
from twisted.internet import reactor, endpoints
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.logger import ILogObserver, globalLogPublisher
from twisted.plugin import IPlugin
from twisted.python import log, usage

from zope.interface import implementer, provider
import time
import cowrie.core.checkers
import cowrie.core.realm
import cowrie.ssh.factory
import cowrie.telnet.factory
from cowrie import core
from cowrie.core.config import CowrieConfig
from cowrie.core.utils import create_endpoint_services, get_endpoints_from_section
from cowrie.pool_interface.handler import PoolHandler
from backend_pool.pool_server import PoolServerFactory

if __version__.major < 17:
    raise ImportError("Your version of Twisted is too old. Please ensure your virtual environment is set up correctly.")


class Options(usage.Options):
    """
    This defines commandline options and flags
    """
    # The '-c' parameters is currently ignored
    optParameters = []

    optFlags = [
        ['help', 'h', 'Display this help and exit.']
    ]


@provider(ILogObserver)
def importFailureObserver(event):
    if 'failure' in event and event['failure'].type is ImportError:
        log.err("ERROR: %s. Please run `pip install -U -r requirements.txt` "
                "from Cowrie's install directory and virtualenv to install "
                "the new dependency" % event['failure'].value.message)


globalLogPublisher.addObserver(importFailureObserver)


@implementer(IServiceMaker, IPlugin)
class CowrieServiceMaker(object):
    tapname = "cowrie"
    description = "She sells sea shells by the sea shore."
    options = Options
    output_plugins = None

    def __init__(self):
        self.topService = None
        self.pool_handler = None

        # ssh is enabled by default
        self.enableSSH = CowrieConfig().getboolean('ssh', 'enabled', fallback=True)
        # telnet is disabled by default
        self.enableTelnet = CowrieConfig().getboolean('telnet', 'enabled', fallback=False)

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in Cowrie.
        """

        if options["help"] is True:
            print("""Usage: twistd [options] cowrie [-h]
Options:
  -h, --help             print this help message.

Makes a Cowrie SSH/Telnet honeypot.
""")
            sys.exit(1)

        if os.name == 'posix' and os.getuid() == 0:
            print('ERROR: You must not run cowrie as root!')
            sys.exit(1)

        tz = CowrieConfig().get('honeypot', 'timezone', fallback='UTC')
        # `system` means use the system time zone
        if tz != 'system':
            os.environ['TZ'] = tz

        log.msg("Python Version {}".format(str(sys.version).replace('\n', '')))
        log.msg("Twisted Version {}.{}.{}".format(__version__.major, __version__.minor, __version__.micro))

        # check configurations
        if not self.enableTelnet and not self.enableSSH:
            print('ERROR: You must at least enable SSH or Telnet')
            sys.exit(1)

        # Load output modules
        self.output_plugins = []
        for x in CowrieConfig().sections():
            if not x.startswith('output_'):
                continue
            if CowrieConfig().getboolean(x, 'enabled') is False:
                continue
            engine = x.split('_')[1]
            try:
                output = __import__('cowrie.output.{}'.format(engine),
                                    globals(), locals(), ['output']).Output()
                log.addObserver(output.emit)
                self.output_plugins.append(output)
                log.msg("Loaded output engine: {}".format(engine))
            except ImportError as e:
                log.err("Failed to load output engine: {} due to ImportError: {}".format(engine, e))
                log.msg("Please install the dependencies for {} listed in requirements-output.txt".format(engine))
            except Exception:
                log.err()
                log.msg("Failed to load output engine: {}".format(engine))

        self.topService = service.MultiService()
        application = service.Application('cowrie')
        self.topService.setServiceParent(application)

        # initialise VM pool handling - only if proxy AND pool set to enabled
        backend_type = CowrieConfig().get('honeypot', 'backend', fallback='shell')
        pool_enabled = CowrieConfig().getboolean('proxy', 'enable_pool', fallback=False)

        if backend_type == 'proxy' and pool_enabled:
            endpoint = TCP4ServerEndpoint(reactor, 3574)
            endpoint.listen(PoolServerFactory())

            self.pool_handler = PoolHandler(self)
        else:
            # we initialise the services directly
            self.pool_ready()

        return self.topService

    def pool_ready(self):
        if self.enableSSH:
            factory = cowrie.ssh.factory.CowrieSSHFactory(self.pool_handler)
            factory.tac = self
            factory.portal = portal.Portal(core.realm.HoneyPotRealm())
            factory.portal.registerChecker(
                core.checkers.HoneypotPublicKeyChecker())
            factory.portal.registerChecker(
                core.checkers.HoneypotPasswordChecker())

            if CowrieConfig().getboolean('ssh', 'auth_none_enabled', fallback=False) is True:
                factory.portal.registerChecker(
                    core.checkers.HoneypotNoneChecker())

            if CowrieConfig().has_section('ssh'):
                listen_endpoints = get_endpoints_from_section(CowrieConfig(), 'ssh', 2222)
            else:
                listen_endpoints = get_endpoints_from_section(CowrieConfig(), 'honeypot', 2222)

            create_endpoint_services(reactor, self.topService, listen_endpoints, factory)

        if self.enableTelnet:
            f = cowrie.telnet.factory.HoneyPotTelnetFactory(self.pool_handler)
            f.tac = self
            f.portal = portal.Portal(core.realm.HoneyPotRealm())
            f.portal.registerChecker(core.checkers.HoneypotPasswordChecker())

            listen_endpoints = get_endpoints_from_section(CowrieConfig(), 'telnet', 2223)
            create_endpoint_services(reactor, self.topService, listen_endpoints, f)


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.
serviceMaker = CowrieServiceMaker()
