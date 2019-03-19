from __future__ import absolute_import, division

from twisted.names import client
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):
    """
    Output plugin used for reverse DNS lookup
    """

    def __init__(self):
        self.timeout = [CONFIG.getint('output_reversedns', 'timeout', fallback=3)]
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
        if entry['eventid'] == 'cowrie.session.connect':
            self.reversedns(entry)

    def reversedns(self, entry):
        """
        Perform a reverse DNS lookup on an IP

        Arguments:
            addr -- IPv4 Address
        """
        src_ip = entry['src_ip']
        ptr = self.reverseNameFromIPAddress(src_ip)
        d = client.lookupPointer(ptr, timeout=self.timeout)

        def cbError(failure):
            log.msg("reversedns: Error in lookup for {}".format(src_ip))
            failure.printTraceback()

        def processResult(result):
            """
            Process the lookup result
            """
            payload = result[0][0].payload
            log.msg(
                eventid='cowrie.reversedns.ptr',
                session=entry['session'],
                format="reversedns: PTR record for IP %(src_ip)s is %(ptr)s ttl=%(ttl)i",
                src_ip=src_ip,
                ptr=str(payload.name).decode('ascii'),
                ttl=payload.ttl)

        d.addCallback(processResult)
        d.addErrback(cbError)
        return d

    def reverseNameFromIPAddress(self, address):
        """
        Reverse the IPv4 address and append in-addr.arpa

        Arguments:
            address {str} -- IP address that is to be reversed
        """
        return '.'.join(reversed(address.split('.'))) + '.in-addr.arpa'
