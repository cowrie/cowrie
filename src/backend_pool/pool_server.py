# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import struct

from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet import reactor, threads
from twisted.python import log

from backend_pool.pool_service import NoAvailableVMs, PoolService


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

            log.msg(eventid='cowrie.backend_pool.server',
                    format='Requesting a VM for attacker @ %(attacker_ip)s',
                    attacker_ip=attacker_ip)

            try:
                guest_id, guest_ip = self.factory.pool_service.request_vm(attacker_ip)
                log.msg(eventid='cowrie.backend_pool.server',
                        format='Providing VM id %(guest_id)s',
                        guest_id=guest_id)

                ssh_port = 22
                telnet_port = 23

                fmt = '!cIIH{0}sHH'.format(len(guest_ip))
                response = struct.pack(fmt, b'r', 0, guest_id, len(guest_ip), guest_ip.encode(), ssh_port, telnet_port)

            except NoAvailableVMs as _:
                log.msg(eventid='cowrie.backend_pool.server',
                        format='No VM available, returning error code')
                response = struct.pack('!cI', b'r', 1)

        elif res_op == b'f':
            recv = struct.unpack('!I', data[1:])
            vm_id = recv[0]

            log.msg(eventid='cowrie.backend_pool.server',
                    format='Freeing VM %(guest_id)s',
                    guest_id=vm_id)

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

    def stopFactory(self):
        log.msg(eventid='cowrie.backend_pool.server',
                format='Stopping backend pool...')

        self.pool_service.stop()

    def buildProtocol(self, addr):
        log.msg(eventid='cowrie.backend_pool.server',
                format='Received connection from %(host)s:%(port)s',
                host=addr.host,
                port=addr.port)
        return PoolServer(self)
