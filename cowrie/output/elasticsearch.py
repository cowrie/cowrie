# Simple elasticsearch logger

from __future__ import division, absolute_import

import pyes

import cowrie.core.output

from cowrie.core.config import CONFIG



class Output(cowrie.core.output.Output):
    """
    """

    def __init__(self):
        """
        """
        self.host = CONFIG.get('output_elasticsearch', 'host')
        self.port = CONFIG.get('output_elasticsearch', 'port')
        self.index =CONFIGg.get('output_elasticsearch', 'index')
        self.type = CONFIG.get('output_elasticsearch', 'type')
        cowrie.core.output.Output.__init__(self)


    def start(self):
        """
        """
        self.es = pyes.ES('{0}:{1}'.format(self.host, self.port))


    def stop(self):
        """
        """
        pass


    def write(self, logentry):
        """
        """
        for i in list(logentry.keys()):
            # remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]

        self.es.index(logentry, self.index, self.type)

