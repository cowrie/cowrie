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

"""
FIXME: This module contains ...
"""

from __future__ import print_function

from zope.interface import implementer

import os
import sys

from twisted.python import log, usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet, service
from twisted.cred import portal

from cowrie.core.config import readConfigFile
from cowrie import core
import cowrie.core.realm
import cowrie.core.checkers

import cowrie.telnet.transport
import cowrie.ssh.factory

class Options(usage.Options):
    """
    FIXME: Docstring
    """
    optParameters = [
        ["port", "p", 0, "The port number to listen on for SSH.", int],
        ["config", "c", 'cowrie.cfg', "The configuration file to use."]
        ]



@implementer(IServiceMaker, IPlugin)
class CowrieServiceMaker(object):
    """
    FIXME: Docstring
    """
    tapname = "cowrie"
    description = "She sells sea shells by the sea shore."
    options = Options
    dbloggers = None
    output_plugins = None
    cfg = None

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in Cowrie.
        """

        if os.name == 'posix' and os.getuid() == 0:
            print('ERROR: You must not run cowrie as root!')
            sys.exit(1)

        cfg = readConfigFile(options["config"])

        # ssh is enabled by default
        if cfg.has_option('ssh', 'enabled') == False or \
           (cfg.has_option('ssh', 'enabled') and \
               cfg.getboolean('ssh', 'enabled') == True):
            enableSSH = True
        else:
            enableSSH = False

        # telnet is disabled by default
        if cfg.has_option('telnet', 'enabled') and \
                 cfg.getboolean('telnet', 'enabled') == True:
            enableTelnet = True
        else:
            enableTelnet = False

        if enableTelnet == False and enableSSH == False:
            print('ERROR: You must at least enable SSH or Telnet')
            sys.exit(1)

        # Load db loggers
        self.dbloggers = []
        for x in cfg.sections():
            if not x.startswith('database_'):
                continue
            engine = x.split('_')[1]
            try:
                dblogger = __import__( 'cowrie.dblog.{}'.format(engine),
                    globals(), locals(), ['dblog']).DBLogger(cfg)
                log.addObserver(dblogger.emit)
                self.dbloggers.append(dblogger)
                log.msg("Loaded dblog engine: {}".format(engine))
            except:
                log.err()
                log.msg("Failed to load dblog engine: {}".format(engine))

        # Load output modules
        self.output_plugins = []
        for x in cfg.sections():
            if not x.startswith('output_'):
                continue
            engine = x.split('_')[1]
            try:
                output = __import__( 'cowrie.output.{}'.format(engine),
                    globals(), locals(), ['output']).Output(cfg)
                log.addObserver(output.emit)
                self.output_plugins.append(output)
                log.msg("Loaded output engine: {}".format(engine))
            except:
                log.err()
                log.msg("Failed to load output engine: {}".format(engine))

        topService = service.MultiService()
        application = service.Application('cowrie')
        topService.setServiceParent(application)

        if enableSSH:
            factory = cowrie.ssh.factory.CowrieSSHFactory(cfg)
            factory.tac = self
            factory.portal = portal.Portal(core.realm.HoneyPotRealm(cfg))
            factory.portal.registerChecker(
                core.checkers.HoneypotPublicKeyChecker())
            factory.portal.registerChecker(
                core.checkers.HoneypotPasswordChecker(cfg))

            if cfg.has_option('honeypot', 'auth_none_enabled') and \
                     cfg.getboolean('honeypot', 'auth_none_enabled') == True:
                factory.portal.registerChecker(
                    core.checkers.HoneypotNoneChecker())

            if cfg.has_option('ssh', 'listen_addr'):
                listen_ssh_addr = cfg.get('ssh', 'listen_addr')
            elif cfg.has_option('honeypot', 'listen_addr'):
                listen_ssh_addr = cfg.get('honeypot', 'listen_addr')
            else:
                listen_ssh_addr = '0.0.0.0'

            # Preference: 1, option, 2, config, 3, default of 2222
            if options['port'] != 0:
                listen_ssh_port = int(options["port"])
            elif cfg.has_option('ssh', 'listen_port'):
                listen_ssh_port = cfg.getint('ssh', 'listen_port')
            elif cfg.has_option('honeypot', 'listen_port'):
                listen_ssh_port = cfg.getint('honeypot', 'listen_port')
            else:
                listen_ssh_port = 2222

            for i in listen_ssh_addr.split():
                svc = internet.TCPServer(listen_ssh_port, factory, interface=i)
                # FIXME: Use addService on topService ?
                svc.setServiceParent(topService)

        if enableTelnet:
            if cfg.has_option('telnet', 'listen_addr'):
                listen_telnet_addr = cfg.get('telnet', 'listen_addr')
            else:
                listen_telnet_addr = '0.0.0.0'

            # Preference: 1, config, 2, default of 2223
            if cfg.has_option('telnet', 'listen_port'):
                listen_telnet_port = cfg.getint('telnet', 'listen_port')
            else:
                listen_telnet_port = 2223

            f = cowrie.telnet.transport.HoneyPotTelnetFactory(cfg)
            f.tac = self
            f.portal = portal.Portal(core.realm.HoneyPotRealm(cfg))
            f.portal.registerChecker(core.checkers.HoneypotPasswordChecker(cfg))
            for i in listen_telnet_addr.split():
                tsvc = internet.TCPServer(listen_telnet_port, f, interface=i)
                # FIXME: Use addService on topService ?
                tsvc.setServiceParent(topService)

        if cfg.has_option('honeypot', 'interact_enabled') and \
                 cfg.getboolean('honeypot', 'interact_enabled') == True:
            iport = int(cfg.get('honeypot', 'interact_port'))
            # FIXME this doesn't support checking both Telnet and SSH sessions
            from cowrie.core import interact
            svc = internet.TCPServer(iport,
                interact.makeInteractFactory(factory), interface='127.0.0.1')
            # FIXME: Use addService on topService ?
            svc.setServiceParent(topService)

        return topService

# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = CowrieServiceMaker()
