# Simple elasticsearch logger

import os
import json

import pyes

import cowrie.core.output


class Output(cowrie.core.output.Output):
    """
    """

    def __init__(self, cfg):
        """
        """
        self.host = cfg.get('output_elasticsearch', 'host')
        self.port = cfg.get('output_elasticsearch', 'port')
        self.index = cfg.get('output_elasticsearch', 'index')
        self.type = cfg.get('output_elasticsearch', 'type')
        cowrie.core.output.Output.__init__(self, cfg)


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

