# SPDX-FileCopyrightText: 2019 Mehtab Zafar <mehtab.zafar98@gmail.com>
# SPDX-FileCopyrightText: 2019-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import ipaddress
from collections import OrderedDict
from typing import Any

from twisted.internet import defer
from twisted.logger import Logger
from twisted.names import client, error

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    Output plugin used for reverse DNS lookup
    """

    _log = Logger()

    timeout: list[int]

    def start(self):
        """
        Start Output Plugin
        """
        self.timeout = [CowrieConfig.getint("output_reversedns", "timeout", fallback=3)]
        self.cache_size: int = 1000
        self._cache: OrderedDict[str, Any] = OrderedDict()

    def stop(self):
        """
        Stop Output Plugin
        """
        pass

    def write(self, event):
        """
        Process log event
        """

        def processConnect(result):
            """
            Create log messages for connect events
            """
            if result is None:
                self._log.info("reversedns: no results (1)")
                return
            if len(result[0]) == 0:
                self._log.info("reversedns: no results (2)")
                return

            payload = result[0][0].payload
            self.dispatch(
                eventid="cowrie.reversedns.connect",
                session=event["session"],
                protocol=event["protocol"],
                format="reversedns: PTR record for IP %(src_ip)s is %(ptr)s"
                " ttl=%(ttl)i",
                src_ip=event["src_ip"],
                ptr=str(payload.name),
                ttl=payload.ttl,
            )

        def processForward(result):
            """
            Create log messages for forward events
            """
            if result is None:
                return
            payload = result[0][0].payload
            self.dispatch(
                eventid="cowrie.reversedns.forward",
                session=event["session"],
                src_ip=event["src_ip"],
                protocol=event["protocol"],
                format="reversedns: PTR record for IP %(dst_ip)s is %(ptr)s"
                " ttl=%(ttl)i",
                dst_ip=event["dst_ip"],
                ptr=str(payload.name),
                ttl=payload.ttl,
            )

        def cbError(failure):
            if failure.type == defer.TimeoutError:
                self._log.info("reversedns: Timeout in DNS lookup")
            elif failure.type == error.DNSNameError:
                # DNSNameError is the NXDOMAIN response
                self._log.info("reversedns: No PTR record returned")
            elif failure.type == error.DNSServerError:
                # DNSServerError is the SERVFAIL response
                self._log.info("reversedns: DNS server not responding")
            else:
                self._log.failure("reversedns: Error in DNS lookup", failure=failure)

        if event["eventid"] == "cowrie.session.connect":
            d = self.reversedns(event["src_ip"])
            if d is not None:
                d.addCallback(processConnect)
                d.addErrback(cbError)
        elif event["eventid"] == "cowrie.direct-tcpip.request":
            d = self.reversedns(event["dst_ip"])
            if d is not None:
                d.addCallback(processForward)
                d.addErrback(cbError)

    def reversedns(self, addr):
        """
        Perform a reverse DNS lookup on an IP, serving repeat lookups
        from a bounded cache of resolved results. A Deferred is single
        use, so the cache holds DNS answers (None for NXDOMAIN), never
        the Deferred itself.

        Arguments:
            addr -- IPv4 Address
        """
        try:
            ptr = ipaddress.ip_address(addr).reverse_pointer
        except ValueError:
            return None
        if addr in self._cache:
            self._cache.move_to_end(addr)
            return defer.succeed(self._cache[addr])
        d = client.lookupPointer(ptr, timeout=self.timeout)
        d.addCallbacks(
            self._cacheResult,
            self._cacheFailure,
            callbackArgs=(addr,),
            errbackArgs=(addr,),
        )
        return d

    def _cacheResult(self, result, addr):
        self._cacheStore(addr, result)
        return result

    def _cacheFailure(self, failure, addr):
        # NXDOMAIN is a definitive answer worth caching; timeouts and
        # SERVFAIL are transient, so the next connect retries the lookup.
        if failure.check(error.DNSNameError):
            self._cacheStore(addr, None)
        return failure

    def _cacheStore(self, addr, result):
        self._cache[addr] = result
        self._cache.move_to_end(addr)
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)
