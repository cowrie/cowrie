# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import struct

from backend_pool.nat import NATService
from backend_pool.pool_service import NoAvailableVMs, PoolService

from twisted.internet.protocol import Factory
from twisted.internet.protocol import Protocol
from twisted.python import log

from cowrie.core.config import CowrieConfig


class PoolServer(Protocol):
    def __init__(self, factory):
        self.factory = factory
        self.local_pool = CowrieConfig().get('proxy', 'pool', fallback='local') == 'local'
        self.pool_only = CowrieConfig().getboolean('backend_pool', 'pool_only', fallback=False)
        self.use_nat = CowrieConfig().getboolean('backend_pool', 'use_nat', fallback=True)

        if self.use_nat:
            self.nat_public_ip = CowrieConfig().get('backend_pool', 'nat_public_ip')

    def dataReceived(self, data):
        res_op = struct.unpack('!c', bytes([data[0]]))[0]  # yes, this needs to be done to extract the op code correctly
        response = None

        if res_op == b'i':
            recv = struct.unpack('!II?', data[1:])

            # set the pool service thread configs
            max_vm = recv[0]
            vm_unused_timeout = recv[1]
            share_guests = recv[2]
            self.factory.pool_service.set_configs(max_vm, vm_unused_timeout, share_guests)

            # respond with ok
            self.factory.initialised = True
            response = struct.pack('!cI', b'i', 0)

        elif res_op == b'r':
            # receives: attacker ip (used to serve same VM to same attacker)
            # sends: status code, guest_id, guest_ip, guest's ssh and telnet port

            recv = struct.unpack('!H', data[1:3])
            ip_len = recv[0]

            recv = struct.unpack('!{0}s'.format(ip_len), data[3:])
            attacker_ip = recv[0].decode()

            log.msg(eventid='cowrie.backend_pool.server',
                    format='Requesting a VM for attacker @ %(attacker_ip)s',
                    attacker_ip=attacker_ip)

            try:
                guest_id, guest_ip, guest_snapshot = self.factory.pool_service.request_vm(attacker_ip)
                log.msg(eventid='cowrie.backend_pool.server',
                        format='Providing VM id %(guest_id)s',
                        guest_id=guest_id)

                ssh_port = CowrieConfig().getint('backend_pool', 'guest_ssh_port', fallback=22)
                telnet_port = CowrieConfig().getint('backend_pool', 'guest_telnet_port', fallback=23)

                # after we receive ip and ports, expose ports in the pool's public interface
                # we use NAT if this pool is being run remotely, and if users choose so
                if not self.local_pool and self.use_nat or self.pool_only:
                    nat_ssh_port, nat_telnet_port = self.factory.nat.request_binding(guest_id, guest_ip,
                                                                                     ssh_port, telnet_port)

                    fmt = '!cIIH{0}sHHH{1}s'.format(len(self.nat_public_ip), len(guest_snapshot))
                    response = struct.pack(fmt, b'r', 0, guest_id, len(self.nat_public_ip), self.nat_public_ip.encode(),
                                           nat_ssh_port, nat_telnet_port, len(guest_snapshot), guest_snapshot.encode())
                else:
                    fmt = '!cIIH{0}sHHH{1}s'.format(len(guest_ip), len(guest_snapshot))
                    response = struct.pack(fmt, b'r', 0, guest_id, len(guest_ip), guest_ip.encode(),
                                           ssh_port, telnet_port, len(guest_snapshot), guest_snapshot.encode())
            except NoAvailableVMs:
                log.msg(eventid='cowrie.backend_pool.server',
                        format='No VM available, returning error code')
                response = struct.pack('!cI', b'r', 1)

        elif res_op == b'f':
            # receives: guest_id
            recv = struct.unpack('!I', data[1:])
            guest_id = recv[0]

            log.msg(eventid='cowrie.backend_pool.server',
                    format='Freeing VM %(guest_id)s',
                    guest_id=guest_id)

            # free the NAT
            if not self.local_pool and self.use_nat or self.pool_only:
                self.factory.nat.free_binding(guest_id)

            # free the vm
            self.factory.pool_service.free_vm(guest_id)

        elif res_op == b'u':
            # receives: guest_id
            recv = struct.unpack('!I', data[1:])
            guest_id = recv[0]

            log.msg(eventid='cowrie.backend_pool.server',
                    format='Re-using VM %(guest_id)s (not used by attacker)',
                    guest_id=guest_id)

            # free the NAT
            if not self.local_pool and self.use_nat or self.pool_only:
                self.factory.nat.free_binding(guest_id)

            # free this connection and allow VM to be re-used
            self.factory.pool_service.reuse_vm(guest_id)

        if response:
            self.transport.write(response)


class PoolServerFactory(Factory):
    def __init__(self):
        self.initialised = False

        # pool handling
        self.pool_service = None

        # NAT service
        self.nat = NATService()

    def startFactory(self):
        # start the pool thread with default configs
        self.pool_service = PoolService()
        self.pool_service.start_pool()

    def stopFactory(self):
        log.msg(eventid='cowrie.backend_pool.server',
                format='Stopping backend pool...')

        self.pool_service.shutdown_pool()

    def buildProtocol(self, addr):
        log.msg(eventid='cowrie.backend_pool.server',
                format='Received connection from %(host)s:%(port)s',
                host=addr.host,
                port=addr.port)
        return PoolServer(self)
