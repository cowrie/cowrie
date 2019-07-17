# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import struct

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor, threads

from pool.pool_service import NoAvailableVMs, PoolService


class PoolServer(Protocol):
    def __init__(self, factory):
        self.factory = factory

    def dataReceived(self, data):
        res_op = struct.unpack('!c', bytes([data[0]]))[0]  # yes, this needs to be done to extract the op code correctly
        response = None

        if res_op == b'i':
            recv = struct.unpack('!II', data[1:])

            # set the pool service thread configs
            max_vm = recv[0]
            vm_unused_timeout = recv[1]
            self.factory.pool_service.set_configs(max_vm, vm_unused_timeout)

            # respond with ok
            self.factory.initialised = True
            response = struct.pack('!cI', b'i', 0)

        elif res_op == b'r':
            recv = struct.unpack('!H', data[1:3])
            ip_len = recv[0]

            recv = struct.unpack('!{0}s'.format(ip_len), data[3:])
            attacker_ip = recv[0].decode()

            print('Requesting a VM for attacker @ {0}'.format(attacker_ip))

            try:
                guest_id, guest_ip = self.factory.pool_service.request_vm(attacker_ip)
                print('Providing VM id {0}'.format(guest_id))

                ssh_port = 22
                telnet_port = 23

                fmt = '!cIIH{0}sHH'.format(len(guest_ip))
                response = struct.pack(fmt, b'r', 0, guest_id, len(guest_ip), guest_ip.encode(), ssh_port, telnet_port)

            except NoAvailableVMs as _:
                print('No VM available, returning error code')
                response = struct.pack('!cI', b'r', 1)

        elif res_op == b'f':
            recv = struct.unpack('!I', data[1:])
            vm_id = recv[0]

            print('Freeing VM {0}'.format(vm_id))

            # free the vm
            self.factory.pool_service.free_vm(vm_id)

        if response:
            self.transport.write(response)


class PoolServerFactory(Factory):
    def __init__(self):
        self.initialised = False

        # pool handling
        self.pool_service = None

    def startFactory(self):
        # start the pool thread with default configs
        self.pool_service = PoolService()
        threads.deferToThread(self.pool_service.producer_loop)

    def buildProtocol(self, addr):
        print('Received connection from {0}:{1}'.format(addr.host, addr.port))
        return PoolServer(self)


# endpoint = TCP4ServerEndpoint(reactor, 3574)
# endpoint.listen(PoolServerFactory())
# reactor.run()
