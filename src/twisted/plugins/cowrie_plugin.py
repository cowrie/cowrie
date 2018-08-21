from __future__ import absolute_import, division, print_function

import configparser
import os
import sys

from twisted._version import __version__
from twisted.application import service
from twisted.application.service import IServiceMaker
from twisted.cred import portal
from twisted.internet import reactor
from twisted.logger import ILogObserver, globalLogPublisher
from twisted.plugin import IPlugin
from twisted.python import log, usage

from zope.interface import implementer, provider

import cowrie.core.checkers
import cowrie.core.realm
import cowrie.ssh.factory
import cowrie.telnet.transport
from cowrie import core
from cowrie.core.config import CONFIG
from cowrie.core.utils import create_endpoint_services, get_endpoints_from_section

if __version__.major < 17:
    raise ImportError("Your version of Twisted is too old. Please ensure your virtual environment is set up correctly.")


class Options(usage.Options):
    """
    This defines commandline options and flags
    """
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
    dbloggers = None
    output_plugins = None

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

        log.msg("Python Version {}".format(str(sys.version).replace('\n', '')))
        log.msg("Twisted Version {}.{}.{}".format(__version__.major, __version__.minor, __version__.micro))

        # ssh is enabled by default
        try:
            enableSSH = CONFIG.getboolean('ssh', 'enabled')
        except (configparser.NoSectionError, configparser.NoOptionError):
            enableSSH = True

        # telnet is disabled by default
        try:
            enableTelnet = CONFIG.getboolean('telnet', 'enabled')
        except (configparser.NoSectionError, configparser.NoOptionError):
            enableTelnet = False

        if enableTelnet is False and enableSSH is False:
            print('ERROR: You must at least enable SSH or Telnet')
            sys.exit(1)

        # Load db loggers
        self.dbloggers = []
        for x in CONFIG.sections():
            if not x.startswith('database_'):
                continue
            engine = x.split('_')[1]
            try:
                dblogger = __import__('cowrie.dblog.{}'.format(engine),
                                      globals(), locals(), ['dblog']).DBLogger()
                log.addObserver(dblogger.emit)
                self.dbloggers.append(dblogger)
                log.msg("Loaded dblog engine: {}".format(engine))
            except Exception:
                log.err()
                log.msg("Failed to load dblog engine: {}".format(engine))

        # Load output modules
        self.output_plugins = []
        for x in CONFIG.sections():
            if not x.startswith('output_'):
                continue
            if CONFIG.getboolean(x, 'enabled') is False:
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

        topService = service.MultiService()
        application = service.Application('cowrie')
        topService.setServiceParent(application)

        if enableSSH:
            factory = cowrie.ssh.factory.CowrieSSHFactory()
            factory.tac = self
            factory.portal = portal.Portal(core.realm.HoneyPotRealm())
            factory.portal.registerChecker(
                core.checkers.HoneypotPublicKeyChecker())
            factory.portal.registerChecker(
                core.checkers.HoneypotPasswordChecker())

            if CONFIG.has_option('honeypot', 'auth_none_enabled') and \
                    CONFIG.getboolean('honeypot', 'auth_none_enabled') is True:
                factory.portal.registerChecker(
                    core.checkers.HoneypotNoneChecker())

            if CONFIG.has_section('ssh'):
                listen_endpoints = get_endpoints_from_section(CONFIG, 'ssh', 2222)
            else:
                listen_endpoints = get_endpoints_from_section(CONFIG, 'honeypot', 2222)

            create_endpoint_services(reactor, topService, listen_endpoints, factory)

        if enableTelnet:
            f = cowrie.telnet.transport.HoneyPotTelnetFactory()
            f.tac = self
            f.portal = portal.Portal(core.realm.HoneyPotRealm())
            f.portal.registerChecker(core.checkers.HoneypotPasswordChecker())

            listen_endpoints = get_endpoints_from_section(CONFIG, 'telnet', 2223)
            create_endpoint_services(reactor, topService, listen_endpoints, f)

        return topService


# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.
serviceMaker = CowrieServiceMaker()
