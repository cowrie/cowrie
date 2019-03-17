from __future__ import absolute_import, division

import IPy

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
        self.enabled = CONFIG.getboolean('output_reversedns', 'enabled')
        self.timeout = list(
            map(int, CONFIG.get('output_reversedns', 'timeout').split(", ")))
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
        if self.enabled:
            log.msg("Reverse DNS for {}".format(entry['src_ip']))
            self.reversedns(entry)

    def reversedns(self, entry):
        """Perform a Reverse DNS lookup on the attacker's IP

        Arguments:
            entry {list} -- list having all the events
        """
        addr = entry.get('src_ip')
        ptr = IPy.IP(addr).reverseName()
        d = client.lookupPointer(ptr, timeout=self.timeout)
        d.addCallback(processResult)
        return d


def processResult(result):
    """process the lookup result
    """
    RR = result[0][0]
    log.msg("Reverse DNS record: {}".format(RR.payload))
