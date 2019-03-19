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
        self.timeout = CONFIG.getint('output_reversedns', 'timeout', fallback=3)
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
            self.reversedns(entry['src_ip'])

    def reversedns(self, addr):
        """
        Perform a reverse DNS lookup on an IP

        Arguments:
            addr -- IPv4 Address
        """
        ptr = self.reverseNameFromIPAddress(addr)
        d = client.lookupPointer(ptr, timeout=self.timeout)

        def cbError(failure):
            log.msg("reversedns: Error in lookup")
            failure.printTraceback()

        def processResult(result):
            """
            Process the lookup result
            """
            RR = result[0][0]
            log.msg("Reverse DNS record for ip={0}: {1}".format(
                addr, RR.payload))

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
