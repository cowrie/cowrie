# SPDX-FileCopyrightText: 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# SPDX-FileCopyrightText: 2021-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

from twisted.internet import defer

from backend_pool.ssh_exec import execute_ssh
from backend_pool.telnet_exec import execute_telnet


class ProxyTestCommand:
    """
    This class executes commands on Proxy instances and their backends (or either one of them).
    If executing on both, it compares their outputs, and a deferred succeeds on that case.
    """

    def __init__(
        self,
        connection_type,
        hostname,
        port_backend,
        port_proxy,
        username_backend,
        password_backend,
        username_proxy,
        password_proxy,
    ):
        self.deferred = defer.Deferred()
        self.backend_data = None
        self.proxy_data = None

        self.hostname = hostname
        self.port_backend = port_backend
        self.port_proxy = port_proxy

        self.username_backend = username_backend
        self.password_backend = password_backend
        self.username_proxy = username_proxy
        self.password_proxy = password_proxy

        # whether to execute the command via SSH or Telnet
        self.execute = execute_ssh if connection_type == "ssh" else execute_telnet

    def execute_both(self, command):
        def callback_backend(data):
            if self.deferred.called:
                return
            # if we haven't received data from the proxy just store the output
            if self.proxy_data is None:
                self.backend_data = data
            else:
                # compare data from proxy and backend
                if data == self.proxy_data:
                    self.deferred.callback(True)
                else:
                    self.deferred.errback(ValueError())

        def callback_proxy(data):
            if self.deferred.called:
                return
            # if we haven't received data from the backend just store the output
            if self.backend_data is None:
                self.proxy_data = data
            else:
                # compare data from proxy and backend
                if data == self.backend_data:
                    self.deferred.callback(True)
                else:
                    self.deferred.errback(
                        ValueError("Values from proxy and backend do not match!")
                    )

        # execute exec command on both backend and proxy
        self.execute(
            self.hostname,
            self.port_backend,
            self.username_backend,
            self.password_backend,
            command,
            callback_backend,
        ).addErrback(self._execution_failed)
        self.execute(
            self.hostname,
            self.port_proxy,
            self.username_proxy,
            self.password_proxy,
            command,
            callback_proxy,
        ).addErrback(self._execution_failed)

    def _execution_failed(self, reason):
        if not self.deferred.called:
            self.deferred.errback(reason)

    def execute_one(self, is_proxy, command, deferred):
        def callback(data):
            if not deferred.called:
                deferred.callback(data)

        def errback(reason):
            if not deferred.called:
                deferred.errback(reason)

        if is_proxy:
            # execute via proxy
            username = self.username_proxy
            password = self.password_proxy
        else:
            # execute via backend
            username = self.username_backend
            password = self.password_backend

        # execute exec command
        self.execute(
            self.hostname, self.port_backend, username, password, command, callback
        ).addErrback(errback)
