# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>

"""
Basic Splunk connector.
Not recommended for production use.
JSON log file is still recommended way to go

IDEA: convert to new HTTP input, no splunk libraries
required then

"""

from __future__ import division, absolute_import

import os
import json

import splunklib.client as client

import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):
    """
    """

    def __init__(self):
        """
        Initializing the class
        """
        self.index = CONFIG.get('output_splunklegacy', 'index')
        self.username = CONFIG.get('output_splunklegacy', 'username')
        self.password = CONFIG.get('output_splunklegacy', 'password')
        self.host = CONFIG.get('output_splunklegacy', 'host')
        self.port = CONFIG.getint('output_splunklegacy', 'port')
        cowrie.core.output.Output.__init__(self)


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

