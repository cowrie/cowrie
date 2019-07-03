# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import struct

from twisted.internet.protocol import ClientFactory, Protocol
from twisted.python import log

from cowrie.core.config import CowrieConfig


class PoolClient(Protocol):
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
        max_vms = CowrieConfig().getint('proxy', 'pool_max_vms')
        vm_unused_timeout = CowrieConfig().getint('proxy', 'pool_vm_unused_timeout')

        buf = struct.pack('!cII', b'i', max_vms, vm_unused_timeout)
        self.transport.write(buf)

    def send_vm_request(self, src_ip):
        fmt = '!cH{0}s'.format(len(src_ip))
        buf = struct.pack(fmt, b'r', len(src_ip), src_ip.encode())

        self.transport.write(buf)

    def send_vm_free(self):
        buf = struct.pack('!cI', b'f', self.vm_id)
        self.transport.write(buf)

    def dataReceived(self, data):
        # only makes sense to process data if we have a parent to send it to
        if not self.parent:
            log.err('Parent not set, discarding data from pool')
            return

        response = struct.unpack('!cI', data[0:5])

        res_op = response[0]
        res_code = response[1]

        if res_op == b'i':
            # callback to the handler to signal that pool was initialised successfully,
            # so that SSH and Telnet setup can proceed
            self.parent.initialisation_response(res_code)

        elif res_op == b'r':
            recv = struct.unpack('!IH', data[5:11])
            self.vm_id = recv[0]
            ip_len = recv[1]

            recv = struct.unpack('!{0}sHH'.format(ip_len), data[11:])
            honey_ip = recv[0]
            ssh_port = recv[1]
            telnet_port = recv[2]

            self.parent.received_pool_data(res_op, res_code, honey_ip, ssh_port, telnet_port)


class PoolClientFactory(ClientFactory):
    def __init__(self, handler):
        pass
        # self.handler = handler

    def buildProtocol(self, addr):
        return PoolClient(self)
