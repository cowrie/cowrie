from __future__ import absolute_import, division

from twisted.names import client
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):
    """one of the output plugins used for
      reverse DNS lookup

    Extends:
        cowrie.core.output.Output
    """

    def __init__(self):
        self.timeout = [int((CONFIG.get('output_reversedns', 'timeout', fallback='3')))]
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
        self.reversedns(entry)

    def reversedns(self, entry):
        """Perform a Reverse DNS lookup on the attacker's IP

        Arguments:
            entry {list} -- list having all the events
        """
        addr = entry.get('src_ip')
        ptr = self.reverseNameFromIPAddress(addr)
        d = client.lookupPointer(ptr, timeout=self.timeout)

        def cbError(failure):
            log.msg("VT: Error in scanfile")
            failure.printTraceback()

        def processResult(result):
            """process the lookup result
            """
            RR = result[0][0]
            log.msg("Reverse DNS record for ip={0}: {1}".format(
                addr, RR.payload))

        d.addCallback(processResult)
        d.addErrback(cbError)
        return d

    def reverseNameFromIPAddress(self, address):
        """Reverse the IPv4 address and append in-addr.arpa

        Arguments:
            address {str} -- IP address that is to be reversed
        """
        return '.'.join(reversed(address.split('.'))) + '.in-addr.arpa'
