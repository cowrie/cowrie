# Copyright (c) 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# See the COPYRIGHT file for more information
from __future__ import annotations

import os
import time
from threading import Lock

from twisted.internet import reactor
from twisted.internet import threads
from twisted.python import log

import backend_pool.libvirt.backend_service
import backend_pool.util
from cowrie.core.config import CowrieConfig


class NoAvailableVMs(Exception):
    pass


class PoolService:
    """
    VM States:
        created -> available -> using -> used -> unavailable -> destroyed

        created:     initialised but not fully booted by QEMU
        available:   can be requested
        using:       a client is connected, can be served for other clients from same ip
        used:        client disconnectec, but can still be served for its ip
        unavailable: marked for destruction after timeout
        destroyed:   deleted by qemu, can be removed from list

    A lock is required to manipulate VMs in states [available, using, used], since these are the ones that can be
    accessed by several consumers and the producer. All other states are accessed only by the single producer.
    """

    def __init__(self, nat_service):
        self.qemu = backend_pool.libvirt.backend_service.LibvirtBackendService()
        self.nat_service = nat_service

        self.guests = []
        self.guest_id: int = 0
        self.guest_lock = Lock()

        # time in seconds between each loop iteration
        self.loop_sleep_time: int = 5
        self.loop_next_call = None

        # default configs; custom values will come from the client when they connect to the pool
        self.max_vm: int = 2
        self.vm_unused_timeout: int = 600
        self.share_guests: bool = True

        # file configs
        self.ssh_port: int = CowrieConfig.getint(
            "backend_pool", "guest_ssh_port", fallback=-1
        )
        self.telnet_port: int = CowrieConfig.getint(
            "backend_pool", "guest_telnet_port", fallback=-1
        )

        self.local_pool: bool = (
            CowrieConfig.get("proxy", "pool", fallback="local") == "local"
        )
        self.pool_only: bool = CowrieConfig.getboolean(
            "backend_pool", "pool_only", fallback=False
        )
        self.use_nat: bool = CowrieConfig.getboolean(
            "backend_pool", "use_nat", fallback=True
        )

        # detect invalid config
        if not self.ssh_port > 0 and not self.telnet_port > 0:
            log.msg(
                eventid="cowrie.backend_pool.service",
                format="Invalid configuration: one of SSH or Telnet ports must be defined!",
            )
            os._exit(1)

        self.any_vm_up: bool = False  # TODO fix for no VM available

    def start_pool(self):
        # cleanup older qemu objects
        self.qemu.destroy_all_cowrie()

        # start backend qemu environment
        self.qemu.start_backend()

        # cleanup references if restarting
        self.guests = []
        self.guest_id = 0

        self.any_vm_up = False  # TODO fix for no VM available

        # start producer
        threads.deferToThread(self.producer_loop)

        # recycle myself after some time
        recycle_period = CowrieConfig.getint(
            "backend_pool", "recycle_period", fallback=-1
        )
        if recycle_period > 0:
            reactor.callLater(recycle_period, self.restart_pool)

    def stop_pool(self):
        # lazy import to avoid exception if not using the backend_pool and libvirt not installed (#1185)
        import libvirt

        log.msg(eventid="cowrie.backend_pool.service", format="Trying pool clean stop")

        # stop loop
        if self.loop_next_call:
            self.loop_next_call.cancel()

        # try destroying all guests
        for guest in self.guests:
            self.qemu.destroy_guest(guest["domain"], guest["snapshot"])

        # force destroy remaining stuff
        self.qemu.destroy_all_cowrie()

        # close any NAT sockets
        if not self.local_pool and self.use_nat or self.pool_only:
            log.msg(
                eventid="cowrie.backend_pool.service", format="Free all NAT bindings"
            )
            self.nat_service.free_all()

        try:
            self.qemu.stop_backend()
        except libvirt.libvirtError:
            print("Not connected to QEMU")  # noqa: T201

    def shutdown_pool(self):
        # lazy import to avoid exception if not using the backend_pool and libvirt not installed (#1185)
        import libvirt

        self.stop_pool()

        try:
            self.qemu.shutdown_backend()
        except libvirt.libvirtError:
            print("Not connected to QEMU")  # noqa: T201

    def restart_pool(self):
        log.msg(
            eventid="cowrie.backend_pool.service",
            format="Refreshing pool, terminating current instances and rebooting",
        )
        self.stop_pool()
        self.start_pool()

    def set_configs(self, max_vm, vm_unused_timeout, share_guests):
        """
        Custom configurations sent from the client are set on the pool here.
        """
        self.max_vm = max_vm
        self.vm_unused_timeout = vm_unused_timeout
        self.share_guests = share_guests

    def get_guest_states(self, states):
        return [g for g in self.guests if g["state"] in states]

    def existing_pool_size(self):
        return len([g for g in self.guests if g["state"] != "destroyed"])

    def is_ip_free(self, ip):
        for guest in self.guests:
            if guest["guest_ip"] == ip:
                return False
        return True

    def has_connectivity(self, ip):
        """
        This method checks if a guest has either SSH or Telnet connectivity, to know whether it is ready for connections
        and healthy. It takes into account whether those services are enabled, and if SSH is enabled and available, then
        no Telnet check needs to be done.
        """
        # check SSH connectivity, if enabled in configs, if disabled then we need to check telnet
        has_ssh = (
            backend_pool.util.nmap_port(ip, self.ssh_port)
            if self.ssh_port > 0
            else False
        )

        # telnet check not needed if has_ssh = True
        has_telnet = (
            backend_pool.util.nmap_port(ip, self.telnet_port)
            if self.telnet_port > 0 and not has_ssh
            else True
        )

        return has_ssh or has_telnet

    # Producers
    def __producer_mark_timed_out(self, guest_timeout: int) -> None:
        """
        Checks timed-out VMs and acquires lock to safely mark for deletion
        """
        self.guest_lock.acquire()
        try:
            # only mark VMs not in use
            used_guests = self.get_guest_states(["used"])
            for guest in used_guests:
                timed_out = (
                    guest["freed_timestamp"] + guest_timeout < backend_pool.util.now()
                )

                # only mark guests without clients
                # (and guest['connected'] == 0) sometimes did not work correctly as some VMs are not signaled as freed
                if timed_out:
                    log.msg(
                        eventid="cowrie.backend_pool.service",
                        format="Guest %(guest_id)s (%(guest_ip)s) marked for deletion (timed-out)",
                        guest_id=guest["id"],
                        guest_ip=guest["guest_ip"],
                    )
                    guest["state"] = "unavailable"
        finally:
            self.guest_lock.release()

    def __producer_check_health(self):
        """
        Checks all usable guests, and whether they should have connectivity. If they don't, then
        mark them for deletion.
        """
        self.guest_lock.acquire()
        try:
            usable_guests = self.get_guest_states(["available", "using", "used"])
            for guest in usable_guests:
                if not self.has_connectivity(guest["guest_ip"]):
                    log.msg(
                        eventid="cowrie.backend_pool.service",
                        format="Guest %(guest_id)s @ %(guest_ip)s has no connectivity... Destroying",
                        guest_id=guest["id"],
                        guest_ip=guest["guest_ip"],
                    )
                    guest["state"] = "unavailable"
        finally:
            self.guest_lock.release()

    def __producer_destroy_timed_out(self):
        """
        Loops over 'unavailable' guests, and invokes qemu to destroy the corresponding domain
        """
        unavailable_guests = self.get_guest_states(["unavailable"])
        for guest in unavailable_guests:
            try:
                self.qemu.destroy_guest(guest["domain"], guest["snapshot"])
                guest["state"] = "destroyed"
            except Exception as error:
                log.err(
                    eventid="cowrie.backend_pool.service",
                    format="Error destroying guest: %(error)s",
                    error=error,
                )

    def __producer_remove_destroyed(self):
        """
        Removes guests marked as destroyed (so no qemu domain existing)
        and simply removes their object from the list
        """
        destroyed_guests = self.get_guest_states(["destroyed"])
        for guest in destroyed_guests:
            self.guests.remove(guest)

    def __producer_mark_available(self):
        """
        Checks recently-booted guests ('created' state), and whether they are accepting SSH or Telnet connections,
        which indicates they are ready to be used ('available' state).

        No lock needed since the 'created' state is only accessed by the single-threaded producer
        """
        created_guests = self.get_guest_states(["created"])
        for guest in created_guests:
            if self.has_connectivity(guest["guest_ip"]):
                self.any_vm_up = True  # TODO fix for no VM available
                guest["state"] = "available"
                boot_time = int(time.time() - guest["start_timestamp"])
                log.msg(
                    eventid="cowrie.backend_pool.service",
                    format="Guest %(guest_id)s ready for connections @ %(guest_ip)s! (boot %(boot_time)ss)",
                    guest_id=guest["id"],
                    guest_ip=guest["guest_ip"],
                    boot_time=boot_time,
                )

    def __producer_create_guests(self):
        """
        Creates guests until the pool has the allotted amount
        """
        # replenish pool until full
        to_create = self.max_vm - self.existing_pool_size()
        for _ in range(to_create):
            dom, snap, guest_ip = self.qemu.create_guest(self.is_ip_free)

            # create guest object
            self.guests.append(
                {
                    "id": self.guest_id,
                    "state": "created",
                    "prev_state": None,  # used in case a guest is requested and freed immediately, to revert the state
                    "start_timestamp": time.time(),
                    "guest_ip": guest_ip,
                    "connected": 0,
                    "client_ips": set(),
                    "freed_timestamp": -1,
                    "domain": dom,
                    "snapshot": snap,
                }
            )

            self.guest_id += 1

            # reset id
            if self.guest_id == 252:
                self.guest_id = 0

    def producer_loop(self):
        # delete old VMs, but do not let pool size be 0
        if self.existing_pool_size() > 1:
            # mark timed-out VMs for destruction
            self.__producer_mark_timed_out(self.vm_unused_timeout)

            # delete timed-out VMs
            self.__producer_destroy_timed_out()

        # checks for guests without connectivity
        self.__producer_check_health()

        # remove destroyed from list
        self.__producer_remove_destroyed()

        # replenish pool until full
        self.__producer_create_guests()

        # check for created VMs that can become available
        self.__producer_mark_available()

        # sleep until next iteration
        self.loop_next_call = reactor.callLater(
            self.loop_sleep_time, self.producer_loop
        )

    # Consumers
    def __consumers_get_guest_ip(self, src_ip):
        self.guest_lock.acquire()
        try:
            # if ip is the same, doesn't matter if being used or not
            usable_guests = self.get_guest_states(["used", "using"])
            for guest in usable_guests:
                if src_ip in guest["client_ips"]:
                    return guest
        finally:
            self.guest_lock.release()

        return None

    def __consumers_get_available_guest(self):
        self.guest_lock.acquire()
        try:
            available_guests = self.get_guest_states(["available"])
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

            usable_guests = self.get_guest_states(["using", "used"])
            for guest in usable_guests:
                if not least_conn or guest["connected"] < least_conn["connected"]:
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
            # TODO fix for no VM available
            if self.any_vm_up:
                log.msg("Inconsistent state in pool, restarting...")
                self.stop_pool()
            raise NoAvailableVMs()

        guest["prev_state"] = guest["state"]
        guest["state"] = "using"
        guest["connected"] += 1
        guest["client_ips"].add(src_ip)

        return guest["id"], guest["guest_ip"], guest["snapshot"]

    def free_vm(self, guest_id):
        self.guest_lock.acquire()
        try:
            for guest in self.guests:
                if guest["id"] == guest_id:
                    guest["freed_timestamp"] = backend_pool.util.now()
                    guest["connected"] -= 1

                    if guest["connected"] == 0:
                        guest["state"] = "used"
                    return
        finally:
            self.guest_lock.release()

    def reuse_vm(self, guest_id):
        self.guest_lock.acquire()
        try:
            for guest in self.guests:
                if guest["id"] == guest_id:
                    guest["connected"] -= 1

                    if guest["connected"] == 0:
                        # revert machine state to previous
                        guest["state"] = guest["prev_state"]
                        guest["prev_state"] = None
                    return
        finally:
            self.guest_lock.release()
