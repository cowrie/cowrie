# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information

import time
from threading import Lock

import backend_pool.libvirt.backend_service
import backend_pool.util

import libvirt

from twisted.internet import reactor
from twisted.python import log


class NoAvailableVMs(Exception):
    pass


class PoolService:
    """
    VM States:
        created -> available -> using -> used -> unavailable -> destroyed

        created:     initialised but not fully booted by Qemu
        available:   can be requested
        using:       a client is connected, can be served for other clients from same ip
        used:        client disconnectec, but can still be served for its ip
        unavailable: marked for destruction after timeout
        destroyed:   deleted by qemu, can be removed from list

    A lock is required to manipulate VMs in states [available, using, used], since these are the ones that can be
    accessed by several consumers and the producer. All other states are accessed only by the single producer.
    """
    def __init__(self):
        self.qemu = backend_pool.libvirt.backend_service.LibvirtBackendService()
        self.guests = []
        self.guest_id = 2
        self.guest_lock = Lock()

        # time in seconds between each loop iteration
        self.loop_sleep_time = 5
        self.loop_next_call = None

        # default configs
        self.max_vm = 2
        self.vm_unused_timeout = 600
        self.share_guests = True

        # cleanup older qemu objects
        self.qemu.destroy_all_cowrie()

        # initialise qemu environment
        self.qemu.initialise_environment()

    def stop(self):
        log.msg(eventid='cowrie.backend_pool.service',
                format='Trying clean shutdown')

        # stop loop
        if self.loop_next_call:
            self.loop_next_call.cancel()

        # force destroy remaining stuff
        self.qemu.destroy_all_cowrie()

        try:
            self.qemu.stop()
        except libvirt.libvirtError:
            print('Not connected to Qemu')

    def set_configs(self, max_vm, vm_unused_timeout, share_guests):
        self.max_vm = max_vm
        self.vm_unused_timeout = vm_unused_timeout
        self.share_guests = share_guests

    def get_guest_states(self, states):
        return [g for g in self.guests if g['state'] in states]

    def existing_pool_size(self):
        return len([g for g in self.guests if g['state'] != 'destroyed'])

    # Producers
    def __producer_mark_timed_out(self, guest_timeout):
        """
        Checks timed-out VMs and acquires lock to safely mark for deletion
        """
        self.guest_lock.acquire()
        try:
            # only mark VMs not in use
            used_guests = self.get_guest_states(['used'])
            for guest in used_guests:
                timed_out = guest['freed_timestamp'] + guest_timeout < backend_pool.util.now()

                # only mark guests without clients
                if timed_out and guest['connected'] == 0:
                    log.msg(eventid='cowrie.backend_pool.service',
                            format='Guest %(guest_id)s (%(guest_ip)s) marked for deletion (timed-out)',
                            guest_id=guest['id'],
                            guest_ip=guest['guest_ip'])
                    guest['state'] = 'unavailable'
        finally:
            self.guest_lock.release()

    def __producer_destroy_timed_out(self):
        """
        Loops over 'unavailable' guests, and invokes qemu to destroy the corresponding domain
        """
        unavailable_guests = self.get_guest_states(['unavailable'])
        for guest in unavailable_guests:
            try:
                self.qemu.destroy_guest(guest['domain'], guest['snapshot'])
                guest['state'] = 'destroyed'
            except Exception as error:
                log.err(eventid='cowrie.backend_pool.service',
                        format='Error destroying guest: %(error)s',
                        error=error)

    def __producer_remove_destroyed(self):
        """
        Removes guests marked as destroyed (so no qemu domain existing)
        and simply removes their object from the list
        """
        destroyed_guests = self.get_guest_states(['destroyed'])
        for guest in destroyed_guests:
            self.guests.remove(guest)

    def __producer_mark_available(self):
        """
        Checks recently-booted guests ('created' state), and whether they are accepting SSH connections,
        which indicates they are ready to be used ('available' state)
        """
        created_guests = self.get_guest_states(['created'])
        for guest in created_guests:
            # TODO check telnet, in particular if SSH is disabled
            if backend_pool.util.nmap_ssh(guest['guest_ip']):
                guest['state'] = 'available'
                boot_time = int(time.time() - guest['start_timestamp'])
                log.msg(eventid='cowrie.backend_pool.service',
                        format='Guest %(guest_id)s ready for SSH connections @ %(guest_ip)s! (boot %(boot_time)ss)',
                        guest_id=guest['id'],
                        guest_ip=guest['guest_ip'],
                        boot_time=boot_time)

    def producer_loop(self):
        # delete old VMs, but do not let pool size be 0
        if self.existing_pool_size() > 1:
            # mark timed-out VMs for destruction
            self.__producer_mark_timed_out(self.vm_unused_timeout)

            # delete timed-out VMs
            self.__producer_destroy_timed_out()

        # remove destroyed from list
        self.__producer_remove_destroyed()

        # replenish pool until full
        create = self.max_vm - self.existing_pool_size()
        for _ in range(create):
            dom, snap, guest_ip = self.qemu.create_guest(self.guest_id)

            self.guests.append({
                'id': self.guest_id,
                'state': 'created',
                'start_timestamp': time.time(),
                'guest_ip': guest_ip,
                'connected': 0,
                'client_ips': set(),
                'freed_timestamp': -1,
                'domain': dom,
                'snapshot': snap
            })

            self.guest_id += 1

            # reset id
            if self.guest_id == 254:
                self.guest_id = 2

        # check for created VMs that can become available
        self.__producer_mark_available()

        # sleep until next iteration
        self.loop_next_call = reactor.callLater(self.loop_sleep_time, self.producer_loop)

    # Consumers
    def __consumers_get_guest_ip(self, src_ip):
        self.guest_lock.acquire()
        try:
            # if ip is the same, doesn't matter if being used or not
            usable_guests = self.get_guest_states(['used', 'using'])
            for guest in usable_guests:
                if src_ip in guest['client_ips']:
                    return guest
        finally:
            self.guest_lock.release()

        return None

    def __consumers_get_available_guest(self):
        self.guest_lock.acquire()
        try:
            available_guests = self.get_guest_states(['available'])
            for guest in available_guests:
                return guest
        finally:
            self.guest_lock.release()

        return None

    def __consumers_get_any_guest(self):
        self.guest_lock.acquire()
        try:
            # try to get a VM with few clients
            least_conn = None

            usable_guests = self.get_guest_states(['using', 'used'])
            for guest in usable_guests:
                if not least_conn or guest['connected'] < least_conn['connected']:
                    least_conn = guest

            return least_conn
        finally:
            self.guest_lock.release()

    # Consumer methods to be called concurrently
    def request_vm(self, src_ip):
        # first check if there is one for the ip
        guest = self.__consumers_get_guest_ip(src_ip)

        if not guest:
            # try to get an available VM
            guest = self.__consumers_get_available_guest()

        # or get any other if policy is to share VMs
        if not guest and self.share_guests:
            guest = self.__consumers_get_any_guest()

        # raise excaption if a valid VM was not found
        if not guest:
            raise NoAvailableVMs()

        guest['state'] = 'using'
        guest['connected'] += 1
        guest['client_ips'].add(src_ip)

        return guest['id'], guest['guest_ip']

    def free_vm(self, guest_id):
        self.guest_lock.acquire()
        try:
            for guest in self.guests:
                if guest['id'] == guest_id:
                    guest['freed_timestamp'] = backend_pool.util.now()
                    guest['connected'] -= 1

                    if guest['connected'] == 0:
                        guest['state'] = 'used'
                    return
        finally:
            self.guest_lock.release()
