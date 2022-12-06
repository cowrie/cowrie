# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import os

from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint
from twisted.python import log

from cowrie.pool_interface.client import PoolClientFactory


class PoolNotReadyError(Exception):
    pass


class PoolHandler:
    """
    When the PoolHandler is started, it establishes a "master" connection to the pool server. After that connection is
    successful (initial_pool_connection_success), it issues an initialisation command to the server. Only after this
    command returns (initialisation_response) connections can use the pool.
    """

    def __init__(self, pool_host, pool_port, cowrie_plugin):
        # used for initialisation only
        self.cowrie_plugin = cowrie_plugin

        # connection details
        self.pool_ip: str = pool_host
        self.pool_port: int = pool_port

        self.pool_ready: bool = False

        self.client_factory = PoolClientFactory(self)

        # create a main connection to set params
        d = self.request_interface(initial_setup=True)
        d.addCallback(self.initial_pool_connection_success)  # TODO error when timeout?
        d.addErrback(self.initial_pool_connection_error)

    def initial_pool_connection_success(self, client):
        log.msg("Initialising pool with Cowrie settings...")
        # TODO get settings from config and send

        client.set_parent(self)
        client.send_initialisation()

    def initial_pool_connection_error(self, reason):
        log.err(f"Could not connect to VM pool: {reason.value}")
        os._exit(1)

    def initialisation_response(self, res_code):
        """
        When the pool's initialisation is successful, signal to the plugin that SSH and Telnet can be started.
        """
        if res_code == 0:
            log.msg("VM pool fully initialised")
            self.pool_ready = True
            self.cowrie_plugin.pool_ready()
        else:
            log.err("VM pool could not initialise correctly!")
            os._exit(1)

    def request_interface(self, initial_setup=False):
        if not initial_setup and not self.pool_ready:
            raise PoolNotReadyError()

        # d.addCallback(self.connectToPoolSuccess)
        # d.addErrback(self.connectToPoolError)
        endpoint = TCP4ClientEndpoint(reactor, self.pool_ip, self.pool_port, timeout=10)
        return endpoint.connect(self.client_factory)
