import os
import json

import splunklib.client as client

import cowrie.core.output

class Output(cowrie.core.output.Output):

    def __init__(self, cfg):
        """ Initializing the class."""
        cowrie.core.output.Output.__init__(self, cfg)
        self.index = self.cfg.get('output_splunk', 'index')
        self.username = self.cfg.get('output_splunk', 'username')
        self.password = self.cfg.get('output_splunk', 'password')
        self.host = self.cfg.get('output_splunk', 'host')
        self.port = self.cfg.get('output_splunk', 'port')

    def start(self):
        self.service = client.connect(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password)
        self.index = self.service.indexes['cowrie']
        pass

    def stop(self):
        pass

    def write(self, logentry):
        for i in logentry.keys():
            # remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]

        mysocket = self.index.attach()
        mysocket.send(json.dumps(logentry))
        mysocket.close()

