# Basic Splunk connector.
# Not recommended for production use.
# JSON log file is still recommended way to go
# 
# IDEA: convert to new HTTP input, no splunk libraries 
# required then
#

import os
import json

import splunklib.client as client

import cowrie.core.output

class Output(cowrie.core.output.Output):

    def __init__(self, cfg):
        """
        Initializing the class
        """
        self.index = cfg.get('output_splunk', 'index')
        self.username = cfg.get('output_splunk', 'username')
        self.password = cfg.get('output_splunk', 'password')
        self.host = cfg.get('output_splunk', 'host')
        self.port = cfg.get('output_splunk', 'port')
        cowrie.core.output.Output.__init__(self, cfg)


    def start(self):
        """
        """
        self.service = client.connect(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password)
        self.index = self.service.indexes['cowrie']


    def stop(self):
        """
        """
        pass


    def write(self, logentry):
        """
        """
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]

        self.mysocket = self.index.attach(
            sourcetype='cowrie',
            host=self.sensor,
            source='cowrie-splunk-connector')
        self.mysocket.send(json.dumps(logentry))
        self.mysocket.close()

