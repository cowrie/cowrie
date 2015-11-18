# Simple elasticsearch logger

import os
import json
import datetime

import pyes 

from twisted.internet import threads

import cowrie.core.output


class Output(cowrie.core.output.Output):


    def __init__(self, cfg):
        self.host = cfg.get('output_elasticsearch', 'host')
        self.port = cfg.get('output_elasticsearch', 'port')
        self.index = cfg.get('output_elasticsearch', 'index')
        self.type = cfg.get('output_elasticsearch', 'type')
        self.daily_index = cfg.get('output_elasticsearch', 'daily_index')
        cowrie.core.output.Output.__init__(self, cfg)


    def start(self):
        pass

    def stop(self):
        pass

    def write(self, logentry):
        for i in logentry.keys():
            # remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]

        def send_to_es():
            es = pyes.ES('{0}:{1}'.format(self.host, self.port))
            if self.daily_index == 'y':
                index = "{}-{}".format(self.index, datetime.date.today().isoformat())
            else:
                index = self.index
            es.index(logentry, index, self.type)
        
        threads.deferToThread(send_to_es)
