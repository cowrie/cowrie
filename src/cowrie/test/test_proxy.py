# -*- test-case-name: Cowrie Proxy Test Cases -*-

# Copyright (c) 2019 Guilherme Borges
# See LICENSE for details.

from __future__ import annotations

import os
import unittest

from cowrie.core.checkers import HoneypotPasswordChecker, HoneypotPublicKeyChecker
from cowrie.core.realm import HoneyPotRealm
from cowrie.ssh.factory import CowrieSSHFactory

from twisted.cred import portal
from twisted.internet import reactor

# from cowrie.test.proxy_compare import ProxyTestCommand

os.environ["COWRIE_HONEYPOT_TTYLOG"] = "false"
os.environ["COWRIE_OUTPUT_JSONLOG_ENABLED"] = "false"


def create_ssh_factory(backend):
    factory = CowrieSSHFactory(backend, None)
    factory.portal = portal.Portal(HoneyPotRealm())
    factory.portal.registerChecker(HoneypotPublicKeyChecker())
    factory.portal.registerChecker(HoneypotPasswordChecker())
    # factory.portal.registerChecker(HoneypotNoneChecker())

    return factory


# def create_telnet_factory(backend):
#     factory = HoneyPotTelnetFactory(backend, None)
#     factory.portal = portal.Portal(HoneyPotRealm())
#     factory.portal.registerChecker(HoneypotPasswordChecker())
#
#     return factory


class ProxyTests(unittest.TestCase):
    """
    How to test the proxy:
        - setUp runs a 'shell' backend on 4444; then set up a 'proxy' on port 5555 connected to the 'shell' backend
        - test_ssh_proxy runs an exec command via a client against both proxy and shell; returns a deferred
        - the deferred succeeds if the output from both is the same
    """

    HOST = "127.0.0.1"

    PORT_BACKEND_SSH = 4444
    PORT_PROXY_SSH = 5555
    PORT_BACKEND_TELNET = 4445
    PORT_PROXY_TELNET = 5556

    USERNAME_BACKEND = "root"
    PASSWORD_BACKEND = "example"

    USERNAME_PROXY = "root"
    PASSWORD_PROXY = "example"

    def setUp(self):
        # ################################################# #
        # #################### Backend #################### #
        # ################################################# #
        # setup SSH backend
        self.factory_shell_ssh = create_ssh_factory("shell")
        self.shell_server_ssh = reactor.listenTCP(
            self.PORT_BACKEND_SSH, self.factory_shell_ssh
        )

        # ################################################# #
        # #################### Proxy ###################### #
        # ################################################# #
        # setup proxy environment
        os.environ["COWRIE_PROXY_BACKEND"] = "simple"
        os.environ["COWRIE_PROXY_BACKEND_SSH_HOST"] = self.HOST
        os.environ["COWRIE_PROXY_BACKEND_SSH_PORT"] = str(self.PORT_BACKEND_SSH)
        os.environ["COWRIE_PROXY_BACKEND_TELNET_HOST"] = self.HOST
        os.environ["COWRIE_PROXY_BACKEND_TELNET_PORT"] = str(self.PORT_BACKEND_TELNET)

        # setup SSH proxy
        self.factory_proxy_ssh = create_ssh_factory("proxy")
        self.proxy_server_ssh = reactor.listenTCP(
            self.PORT_PROXY_SSH, self.factory_proxy_ssh
        )

    # def test_ls(self):
    #     command_tester = ProxyTestCommand('ssh', self.HOST, self.PORT_BACKEND_SSH, self.PORT_PROXY_SSH,
    #                                       self.USERNAME_BACKEND, self.PASSWORD_BACKEND,
    #                                       self.USERNAME_PROXY, self.PASSWORD_PROXY)
    #
    #     return command_tester.execute_both('ls -halt')

    def tearDown(self):
        for client in self.factory_proxy_ssh.running:
            if client.transport:
                client.transport.loseConnection()

        self.proxy_server_ssh.stopListening()
        self.shell_server_ssh.stopListening()

        self.factory_shell_ssh.stopFactory()
        self.factory_proxy_ssh.stopFactory()
