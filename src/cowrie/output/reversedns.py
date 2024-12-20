from __future__ import annotations

from functools import lru_cache
import ipaddress

from twisted.internet import defer
from twisted.names import client, error
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    Output plugin used for reverse DNS lookup
    """

    timeout: list[int]

    def start(self):
        """
        Start Output Plugin
        """
        self.timeout = [CowrieConfig.getint("output_reversedns", "timeout", fallback=3)]

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
                log.msg("reversedns: no results (1)")
                return
            if len(result[0]) == 0:
                log.msg("reversedns: no results (2)")
                return

            payload = result[0][0].payload
            log.msg(
                eventid="cowrie.reversedns.connect",
                session=event["session"],
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
            log.msg(
                eventid="cowrie.reversedns.forward",
                session=event["session"],
                format="reversedns: PTR record for IP %(dst_ip)s is %(ptr)s"
                " ttl=%(ttl)i",
                dst_ip=event["dst_ip"],
                ptr=str(payload.name),
                ttl=payload.ttl,
            )

        def cbError(failure):
            if failure.type == defer.TimeoutError:
                log.msg("reversedns: Timeout in DNS lookup")
            elif failure.type == error.DNSNameError:
                # DNSNameError is the NXDOMAIN response
                log.msg("reversedns: No PTR record returned")
            elif failure.type == error.DNSServerError:
                # DNSServerError is the SERVFAIL response
                log.msg("reversedns: DNS server not responding")
            else:
                log.msg("reversedns: Error in DNS lookup")
                failure.printTraceback()

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

    @lru_cache(maxsize=1000)
    def reversedns(self, addr):
        """
        Perform a reverse DNS lookup on an IP

        Arguments:
            addr -- IPv4 Address
        """
        try:
            ptr = ipaddress.ip_address(addr).reverse_pointer
        except ValueError:
            return None
        d = client.lookupPointer(ptr, timeout=self.timeout)
        return d
