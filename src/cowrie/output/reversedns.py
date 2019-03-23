from __future__ import absolute_import, division

# `ipaddress` system library only on Python3.4+
import ipaddress

from twisted.names import client
from twisted.python import log
from twisted.internet import defer

import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):
    """
    Output plugin used for reverse DNS lookup
    """

    def __init__(self):
        self.timeout = [CONFIG.getint(
            'output_reversedns', 'timeout', fallback=3)]
        cowrie.core.output.Output.__init__(self)

    def start(self):
        """
        Start Output Plugin
        """
        pass

    def stop(self):
        """
        Stop Output Plugin
        """
        pass

    def write(self, entry):
        """
        Process log entry
        """
        def processConnect(result):
            """
            Create log messages for connect events
            """
            payload = result[0][0].payload
            log.msg(
                eventid='cowrie.reversedns.connect',
                session=entry['session'],
                format="reversedns: PTR record for IP %(src_ip)s is %(ptr)s"
                       "ttl=%(ttl)i",
                src_ip=entry['src_ip'],
                ptr=str(payload.name),
                ttl=payload.ttl)

        def processForward(result):
            """
            Create log messages for forward events
            """
            payload = result[0][0].payload
            log.msg(
                eventid='cowrie.reversedns.forward',
                session=entry['session'],
                format="reversedns: PTR record for IP %(dst_ip)s is %(ptr)s"
                       "ttl=%(ttl)i",
                dst_ip=entry['dst_ip'],
                ptr=str(payload.name),
                ttl=payload.ttl)

        if entry['eventid'] == 'cowrie.session.connect':
            d = self.reversedns(entry['src_ip'])
            d.addCallBack(processConnect)
        elif entry['eventid'] == 'cowrie.direct-tcpip.request':
            try:
                ipaddress.ipaddress(entry['dst_ip'])
            except:
                return
            self.reversedns(entry['dst_ip'])
            d.addCallBack(processForward)

    def reversedns(self, addr):
        """
        Perform a reverse DNS lookup on an IP

        Arguments:
            addr -- IPv4 Address
        """
        ptr = self.reverseNameFromIPAddress(addr)
        d = client.lookupPointer(ptr, timeout=self.timeout)

        def cbError(failure):
            if failure.type == defer.TimeoutError:
                log.msg("reversedns: Timeout in lookup for {}".format(addr))
            else:
                log.msg("reversedns: Error in lookup for {}".format(addr))
                failure.printTraceback()

        d.addErrback(cbError)
        return d

    @classmethod
    def reverseNameFromIPAddress(self, address):
        """
        Reverse the IPv4 address and append in-addr.arpa

        Arguments:
            address {str} -- IP address that is to be reversed
        """
        return '.'.join(reversed(address.split('.'))) + '.in-addr.arpa'
