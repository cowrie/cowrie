# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

import struct

from twisted.internet.protocol import ClientFactory, Protocol
from twisted.python import log

from cowrie.core.config import CowrieConfig


class PoolClient(Protocol):
    """
    Represents the connection between a protocol instance (SSH or Telnet) and a QEMU pool
    """

    def __init__(self, factory):
        self.factory = factory
        self.parent = None
        self.vm_id = None  # used when disconnecting

    def connectionMade(self):
        pass

    def set_parent(self, parent):
        self.parent = parent

    def send_initialisation(self):
        """
        Used only by the PoolHandler on the first connection, to set the pool up.
        """
        max_vms = CowrieConfig.getint("proxy", "pool_max_vms", fallback=2)
        vm_unused_timeout = CowrieConfig.getint(
            "proxy", "pool_vm_unused_timeout", fallback=600
        )
        share_guests = CowrieConfig.getboolean(
            "proxy", "pool_share_guests", fallback=True
        )

        buf = struct.pack("!cII?", b"i", max_vms, vm_unused_timeout, share_guests)
        self.transport.write(buf)

    def send_vm_request(self, src_ip):
        fmt = f"!cH{len(src_ip)}s"
        buf = struct.pack(fmt, b"r", len(src_ip), src_ip.encode())

        self.transport.write(buf)

    def send_vm_free(self, backend_dirty):
        # free the guest, if we had any guest in this connection to begin with
        if self.vm_id is not None:
            op_code = b"f" if backend_dirty else b"u"
            buf = struct.pack("!cI", op_code, self.vm_id)
            self.transport.write(buf)

    def dataReceived(self, data):
        # only makes sense to process data if we have a parent to send it to
        if not self.parent:
            log.err("Parent not set, discarding data from pool")
            return

        response = struct.unpack("!cI", data[0:5])

        res_op = response[0]
        res_code = response[1]

        # shift data forward
        data = data[5:]

        if res_op == b"i":
            # callback to the handler to signal that pool was initialised successfully,
            # so that SSH and Telnet setup can proceed
            self.parent.initialisation_response(res_code)

        elif res_op == b"r":
            if res_code != 0:
                log.msg(
                    eventid="cowrie.pool_client",
                    format="Error in pool while requesting guest. Losing connection...",
                )
                self.parent.loseConnection()
                return

            # extract VM id
            recv = struct.unpack("!I", data[:4])
            self.vm_id = recv[0]
            data = data[4:]

            # extract IP
            recv = struct.unpack("!H", data[:2])
            ip_len = recv[0]
            data = data[2:]

            recv = struct.unpack(f"!{ip_len}s", data[:ip_len])
            honey_ip = recv[0]
            data = data[ip_len:]

            # extract ports for SSH and Telnet
            recv = struct.unpack("!HH", data[:4])
            ssh_port = recv[0]
            telnet_port = recv[1]
            data = data[4:]

            # extract snapshot path
            recv = struct.unpack("!H", data[:2])
            snaphsot_len = recv[0]
            data = data[2:]

            recv = struct.unpack(f"!{snaphsot_len}s", data[:snaphsot_len])
            snapshot = recv[0]
            data = data[snaphsot_len:]

            self.parent.received_pool_data(
                res_op, res_code, honey_ip, snapshot, ssh_port, telnet_port
            )


class PoolClientFactory(ClientFactory):
    def __init__(self, handler):
        pass
        # self.handler = handler

    def buildProtocol(self, addr):
        return PoolClient(self)
