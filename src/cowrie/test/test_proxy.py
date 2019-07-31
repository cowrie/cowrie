# -*- test-case-name: Cowrie Proxy Test Cases -*-

# Copyright (c) 2019 Guilherme Borges
# See LICENSE for details.

from __future__ import absolute_import, division

import os

from twisted.internet import reactor, defer
from twisted.trial import unittest
from twisted.cred import portal

from backend_pool.ssh_exec import execute_ssh
import cowrie.core.checkers
import cowrie.core.realm
from cowrie import core
from cowrie.core.config import CowrieConfig
from cowrie.ssh.factory import CowrieSSHFactory

# os.environ["HONEYPOT_LOG_PATH"] = "../../../../var/log/cowrie"
# os.environ["HONEYPOT_DOWNLOAD_PATH"] = "../../../../var/lib/cowrie/downloads"
# os.environ["HONEYPOT_SHARE_PATH"] = "../../../../share/cowrie"
# os.environ["HONEYPOT_STATE_PATH"] = "../../../../var/lib/cowrie"
# os.environ["HONEYPOT_ETC_PATH"] = "../../../../etc"
# os.environ["HONEYPOT_CONTENTS_PATH"] = "../../../../honeyfs"
# os.environ["HONEYPOT_TXTCMDS_PATH"] = "../../../../txtcmds"
#
# os.environ["SHELL_FILESYSTEM"] = "../../../../share/cowrie/fs.pickle"
# os.environ["SHELL_PROCESSES"] = "../../../../share/cowrie/cmdoutput.json"

# os.environ["SSH_RSA_PUBLIC_KEY"] = "../../../../var/lib/cowrie/ssh_host_rsa_key.pub"
# os.environ["SSH_RSA_PRIVATE_KEY"] = "../../../../var/lib/cowrie/ssh_host_rsa_key"
# os.environ["SSH_DSA_PUBLIC_KEY"] = "../../../../var/lib/cowrie/ssh_host_dsa_key.pub"
# os.environ["SSH_DSA_PRIVATE_KEY"] = "../../../../var/lib/cowrie/ssh_host_dsa_key"

os.environ["HONEYPOT_TTYLOG"] = "false"
os.environ["OUTPUT_JSONLOG_ENABLED"] = "false"


def create_ssh_factory(backend):
    factory = CowrieSSHFactory(None, backend)
    factory.portal = portal.Portal(core.realm.HoneyPotRealm())
    factory.portal.registerChecker(core.checkers.HoneypotPublicKeyChecker())
    factory.portal.registerChecker(core.checkers.HoneypotPasswordChecker())
    factory.portal.registerChecker(core.checkers.HoneypotNoneChecker())

    return factory


class ProxyTests(unittest.TestCase):
    def setUp(self):
        os.chdir("../../../../")

        self.factory_shell = create_ssh_factory('shell')
        self.shell_server = reactor.listenTCP(4444, self.factory_shell)

        # Proxy
        os.environ["PROXY_BACKEND"] = "simple"

        os.environ["PROXY_BACKEND_SSH_HOST"] = "localhost"
        os.environ["PROXY_BACKEND_SSH_PORT"] = "4444"
        os.environ["PROXY_BACKEND_TELNET_HOST"] = "localhost"
        os.environ["PROXY_BACKEND_TELNET_PORT"] = "4445"

        self.factory_proxy = create_ssh_factory('proxy')
        self.proxy_server = reactor.listenTCP(5555, self.factory_proxy)

    def test_ssh_proxy(self):
        self.ssh_callback = defer.Deferred()
        execute_ssh('127.0.0.1', 5555, 'root', 'root', 'ls -halt', self.call)
        return self.ssh_callback

    def call(self, data):
        expected = \
            b'drwx------ 1 root root 4096 2013-04-05 13:25 .\r\n' \
            b'drwx------ 1 root root 4096 2013-04-05 13:25 ..\r\n' \
            b'drwx------ 1 root root 4096 2013-04-05 12:58 .aptitude\r\n' \
            b'-rw-r--r-- 1 root root  570 2013-04-05 12:52 .bashrc\r\n' \
            b'-rw-r--r-- 1 root root  140 2013-04-05 12:52 .profile\r\n' \
            b'drwx------ 1 root root 4096 2013-04-05 13:05 .ssh\r\n'

        if data == expected:
            self.ssh_callback.callback(True)
        else:
            self.ssh_callback.errback(ValueError())

    def tearDown(self):
        for x in self.factory_proxy.running:
            x.loseConnection()

        self.proxy_server.stopListening()
        self.shell_server.stopListening()

        self.factory_shell.stopFactory()
        self.factory_proxy.stopFactory()
