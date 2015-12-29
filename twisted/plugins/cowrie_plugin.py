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

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from twisted.application import internet, service
from twisted.cred import portal

from cowrie.core.config import readConfigFile
from cowrie import core
import cowrie.core.realm
import cowrie.core.checkers

import cowrie.ssh.transport

class Options(usage.Options):
    """
    FIXME: Docstring
    """
    optParameters = [
        ["port", "p", 0, "The port number to listen on.", int],
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

    def makeService(self, options):
        """
        Construct a TCPServer from a factory defined in Cowrie.
        """

        if os.name == 'posix' and os.getuid() == 0:
            print('ERROR: You must not run cowrie as root!')
            sys.exit(1)

        cfg = readConfigFile(options["config"])

        top_service = service.MultiService()
        application = service.Application('cowrie')
        top_service.setServiceParent(application)

        factory = cowrie.ssh.transport.HoneyPotSSHFactory(cfg)

        factory.portal = portal.Portal(core.realm.HoneyPotRealm(cfg))
        factory.portal.registerChecker(
            core.checkers.HoneypotPublicKeyChecker())
        factory.portal.registerChecker(
            core.checkers.HoneypotPasswordChecker(cfg))

        if cfg.has_option('honeypot', 'auth_none_enabled') and \
                 cfg.get('honeypot', 'auth_none_enabled').lower() in \
                 ('yes', 'true', 'on'):
            factory.portal.registerChecker(
                core.checkers.HoneypotNoneChecker())


        if cfg.has_option('honeypot', 'listen_addr'):
            listen_addr = cfg.get('honeypot', 'listen_addr')
        else:
            listen_addr = '0.0.0.0'

        # Preference: 1, option, 2, config, 3, default of 2222
        if options['port'] != 0:
            listen_port = int(options["port"])
        elif cfg.has_option('honeypot', 'listen_port'):
            listen_port = int(cfg.get('honeypot', 'listen_port'))
        else:
            listen_port = 2222

        for i in listen_addr.split():
            svc = internet.TCPServer(listen_port, factory, interface=i)
            # FIXME: Use addService on top_service ?
            svc.setServiceParent(top_service)

        if cfg.has_option('honeypot', 'interact_enabled') and \
                 cfg.get('honeypot', 'interact_enabled').lower() in \
                 ('yes', 'true', 'on'):
            iport = int(cfg.get('honeypot', 'interact_port'))
            from cowrie.core import interact
            svc = internet.TCPServer(iport,
                interact.makeInteractFactory(factory), interface='127.0.0.1')
            # FIXME: Use addService on top_service ?
            svc.setServiceParent(top_service)

        return top_service

# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = CowrieServiceMaker()
