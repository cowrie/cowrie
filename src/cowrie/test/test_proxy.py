# -*- test-case-name: Cowrie Proxy Test Cases -*-

# Copyright (c) 2019 Guilherme Borges
# See LICENSE for details.

from __future__ import annotations

import os
import unittest

from cowrie.core.checkers import HoneypotPasswordChecker, HoneypotPublicKeyChecker
from cowrie.shell.realm import HoneyPotRealm
from cowrie.ssh.factory import CowrieSSHFactory

from twisted.cred import portal
from twisted.internet import defer, reactor

from backend_pool.ssh_exec import execute_ssh

os.environ["COWRIE_HONEYPOT_TTYLOG"] = "false"
os.environ["COWRIE_OUTPUT_JSONLOG_ENABLED"] = "false"


def create_ssh_factory(backend):
    factory = CowrieSSHFactory(backend, None)
    factory.portal = portal.Portal(HoneyPotRealm())
    factory.portal.registerChecker(HoneypotPublicKeyChecker())
    factory.portal.registerChecker(HoneypotPasswordChecker())

    return factory


class ProxySSHSmokeTests(unittest.TestCase):
    """
    Smoke tests for SSH proxy functionality.

    Tests that the proxy can forward SSH exec commands to the shell backend
    and return correct output.
    """

    HOST = "127.0.0.1"
    PORT_BACKEND_SSH = 4444
    PORT_PROXY_SSH = 5555

    USERNAME = "root"
    PASSWORD = "example"

    @classmethod
    def setUpClass(cls):
        # Setup proxy environment before creating factories
        os.environ["COWRIE_PROXY_BACKEND"] = "simple"
        os.environ["COWRIE_PROXY_BACKEND_SSH_HOST"] = cls.HOST
        os.environ["COWRIE_PROXY_BACKEND_SSH_PORT"] = str(cls.PORT_BACKEND_SSH)

        # Setup SSH shell backend
        cls.factory_shell_ssh = create_ssh_factory("shell")
        cls.shell_server_ssh = reactor.listenTCP(
            cls.PORT_BACKEND_SSH, cls.factory_shell_ssh
        )

        # Setup SSH proxy pointing to backend
        cls.factory_proxy_ssh = create_ssh_factory("proxy")
        cls.proxy_server_ssh = reactor.listenTCP(
            cls.PORT_PROXY_SSH, cls.factory_proxy_ssh
        )

    @classmethod
    def tearDownClass(cls):
        cls.proxy_server_ssh.stopListening()
        cls.shell_server_ssh.stopListening()

        cls.factory_shell_ssh.stopFactory()
        cls.factory_proxy_ssh.stopFactory()

    def test_proxy_whoami(self):
        """Test that 'whoami' command works through proxy."""
        d = execute_ssh(
            self.HOST,
            self.PORT_PROXY_SSH,
            self.USERNAME,
            self.PASSWORD,
            b"whoami",
        )

        def check_result(data):
            self.assertIn(b"root", data)

        d.addCallback(check_result)
        return d

    def test_proxy_echo(self):
        """Test that 'echo' command works through proxy."""
        d = execute_ssh(
            self.HOST,
            self.PORT_PROXY_SSH,
            self.USERNAME,
            self.PASSWORD,
            b"echo hello",
        )

        def check_result(data):
            self.assertIn(b"hello", data)

        d.addCallback(check_result)
        return d

    def test_proxy_id(self):
        """Test that 'id' command works through proxy."""
        d = execute_ssh(
            self.HOST,
            self.PORT_PROXY_SSH,
            self.USERNAME,
            self.PASSWORD,
            b"id",
        )

        def check_result(data):
            self.assertIn(b"uid=0(root)", data)

        d.addCallback(check_result)
        return d

    def test_proxy_matches_backend(self):
        """Test that proxy output matches direct backend output."""
        results = {"backend": None, "proxy": None}

        def store_backend(data):
            results["backend"] = data

        def store_proxy(data):
            results["proxy"] = data

        d_backend = execute_ssh(
            self.HOST,
            self.PORT_BACKEND_SSH,
            self.USERNAME,
            self.PASSWORD,
            b"uname -a",
        )
        d_backend.addCallback(store_backend)

        d_proxy = execute_ssh(
            self.HOST,
            self.PORT_PROXY_SSH,
            self.USERNAME,
            self.PASSWORD,
            b"uname -a",
        )
        d_proxy.addCallback(store_proxy)

        d = defer.DeferredList([d_backend, d_proxy])

        def compare_results(_):
            self.assertEqual(results["backend"], results["proxy"])

        d.addCallback(compare_results)
        return d
