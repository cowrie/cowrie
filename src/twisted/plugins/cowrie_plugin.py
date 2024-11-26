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

from importlib import import_module
import os
import sys
from typing import ClassVar, TYPE_CHECKING

from zope.interface import implementer, provider

from twisted._version import __version__ as __twisted_version__
from twisted.application import service
from twisted.application.service import IServiceMaker
from twisted.cred import portal
from twisted.internet import reactor
from twisted.logger import ILogObserver, globalLogPublisher
from twisted.plugin import IPlugin
from twisted.python import log, usage

import cowrie.core.checkers
import cowrie.core.realm
import cowrie.ssh.factory
import cowrie.telnet.factory
from backend_pool.pool_server import PoolServerFactory
from cowrie import core
from cowrie._version import __version__ as __cowrie_version__
from cowrie.core.config import CowrieConfig
from cowrie.core.utils import create_endpoint_services, get_endpoints_from_section
from cowrie.pool_interface.handler import PoolHandler

if TYPE_CHECKING:
    from collections.abc import Callable


class Options(usage.Options):
    """
    This defines commandline options and flags
    """

    # The '-c' parameters is currently ignored
    optParameters: ClassVar[list[str]] = []
    optFlags: ClassVar[list[list[str]]] = [["help", "h", "Display this help and exit."]]


@provider(ILogObserver)
def importFailureObserver(event: dict) -> None:
    if "failure" in event and event["failure"].type is ImportError:
        log.err(
            "ERROR: {}. Please run `pip install -U -r requirements.txt` "
            "from Cowrie's install directory and virtualenv to install "
            "the new dependency".format(event["failure"].value.message)
        )


globalLogPublisher.addObserver(importFailureObserver)


@implementer(IServiceMaker, IPlugin)
class CowrieServiceMaker:
    tapname: ClassVar[str] = "cowrie"
    description: ClassVar[str] = "She sells sea shells by the sea shore."
    options = Options
    output_plugins: list[Callable]
    topService: service.Service

    def __init__(self) -> None:
        self.pool_handler = None

        self.output_plugins = []

        # ssh is enabled by default
        self.enableSSH: bool = CowrieConfig.getboolean("ssh", "enabled", fallback=True)

        # telnet is disabled by default
        self.enableTelnet: bool = CowrieConfig.getboolean(
            "telnet", "enabled", fallback=False
        )

        # pool is disabled by default, but need to check this setting in case user only wants to run the pool
        self.pool_only: bool = CowrieConfig.getboolean(
            "backend_pool", "pool_only", fallback=False
        )

    def makeService(self, options: dict) -> service.Service:
        """
        Construct a TCPServer from a factory defined in Cowrie.
        """

        if options["help"] is True:
            print(  # noqa: T201
                """Usage: twistd [options] cowrie [-h]
Options:
  -h, --help             print this help message.

Makes a Cowrie SSH/Telnet honeypot.
"""
            )
            sys.exit(1)

        if os.name == "posix" and os.getuid() == 0:
            print("ERROR: You must not run cowrie as root!")  # noqa: T201
            sys.exit(1)

        tz: str = CowrieConfig.get("honeypot", "timezone", fallback="UTC")
        # `system` means use the system time zone
        if tz != "system":
            os.environ["TZ"] = tz

        log.msg("Python Version {}".format(str(sys.version).replace("\n", "")))
        log.msg(
            f"Twisted Version {__twisted_version__.major}.{__twisted_version__.minor}.{__twisted_version__.micro}"
        )
        log.msg(
            f"Cowrie Version {__cowrie_version__.major}.{__cowrie_version__.minor}.{__cowrie_version__.micro}"
        )

        # check configurations
        if not self.enableTelnet and not self.enableSSH and not self.pool_only:
            print(  # noqa: T201
                "ERROR: You must at least enable SSH or Telnet, or run the backend pool"
            )
            sys.exit(1)

        # Load output modules
        self.output_plugins = []
        for x in CowrieConfig.sections():
            if not x.startswith("output_"):
                continue
            if CowrieConfig.getboolean(x, "enabled", fallback=False) is False:
                continue
            engine: str = x.split("_")[1]
            try:
                output = import_module(f"cowrie.output.{engine}").Output()
                log.addObserver(output.emit)
                self.output_plugins.append(output)
                log.msg(f"Loaded output engine: {engine}")
            except ImportError as e:
                log.err(
                    f"Failed to load output engine: {engine} due to ImportError: {e}"
                )
                log.msg(
                    f"Please install the dependencies for {engine} listed in requirements-output.txt"
                )
            except Exception:
                log.err()
                log.msg(f"Failed to load output engine: {engine}")

        self.topService = service.MultiService()
        application = service.Application("cowrie")
        self.topService.setServiceParent(application)

        # initialise VM pool handling - only if proxy AND pool set to enabled, and pool is to be deployed here
        # or also enabled if pool_only is true
        backend_type: str = CowrieConfig.get("honeypot", "backend", fallback="shell")
        proxy_backend: str = CowrieConfig.get("proxy", "backend", fallback="simple")

        if (backend_type == "proxy" and proxy_backend == "pool") or self.pool_only:
            # in this case we need to set some kind of pool connection

            local_pool: bool = (
                CowrieConfig.get("proxy", "pool", fallback="local") == "local"
            )
            pool_host: str = CowrieConfig.get(
                "proxy", "pool_host", fallback="127.0.0.1"
            )
            pool_port: int = CowrieConfig.getint("proxy", "pool_port", fallback=6415)

            if local_pool or self.pool_only:
                # start a pool locally
                f = PoolServerFactory()
                f.tac = self  # type: ignore

                listen_endpoints = get_endpoints_from_section(
                    CowrieConfig, "backend_pool", 6415
                )
                create_endpoint_services(reactor, self.topService, listen_endpoints, f)

                pool_host = "127.0.0.1"  # force use of local interface

            # either way (local or remote) we set up a client to the pool
            # unless this instance has no SSH and Telnet (pool only)
            if (self.enableTelnet or self.enableSSH) and not self.pool_only:
                self.pool_handler = PoolHandler(pool_host, pool_port, self)  # type: ignore

        else:
            # we initialise the services directly
            self.pool_ready()

        return self.topService

    def pool_ready(self) -> None:
        backend: str = CowrieConfig.get("honeypot", "backend", fallback="shell")

        # this method is never called if self.pool_only is False,
        # since we do not start the pool handler that would call it
        if self.enableSSH:
            factory = cowrie.ssh.factory.CowrieSSHFactory(backend, self.pool_handler)
            factory.tac = self  # type: ignore
            factory.portal = portal.Portal(core.realm.HoneyPotRealm())
            factory.portal.registerChecker(core.checkers.HoneypotPublicKeyChecker())
            factory.portal.registerChecker(core.checkers.HoneypotPasswordChecker())

            if CowrieConfig.getboolean("ssh", "auth_none_enabled", fallback=False):
                factory.portal.registerChecker(core.checkers.HoneypotNoneChecker())

            if CowrieConfig.has_section("ssh"):
                listen_endpoints = get_endpoints_from_section(CowrieConfig, "ssh", 2222)
            else:
                listen_endpoints = get_endpoints_from_section(
                    CowrieConfig, "honeypot", 2222
                )

            create_endpoint_services(
                reactor, self.topService, listen_endpoints, factory
            )

        if self.enableTelnet:
            f = cowrie.telnet.factory.HoneyPotTelnetFactory(backend, self.pool_handler)
            f.tac = self
            f.portal = portal.Portal(core.realm.HoneyPotRealm())
            f.portal.registerChecker(core.checkers.HoneypotPasswordChecker())

            listen_endpoints = get_endpoints_from_section(CowrieConfig, "telnet", 2223)
            create_endpoint_services(reactor, self.topService, listen_endpoints, f)


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.
serviceMaker = CowrieServiceMaker()
