"""
Simple Graylog HTTP Graylog Extended Log Format (GELF) logger.
"""

import cowrie.core.output
import json
import os
import requests
import time

from cowrie.core.config import CowrieConfig


url: bytes


class Output(cowrie.core.output.Output):
    def start(self):
        self.url = CowrieConfig.get("output_graylog_gelf", "url")
        self.tls = CowrieConfig.get("output_graylog_gelf", "tls")
        if 'True' in self.tls:
            self.cert = CowrieConfig.get("output_graylog_gelf", "cert")
            self.cert_key = CowrieConfig.get("output_graylog_gelf", "key")
            self.verify = CowrieConfig.get("output_graylog_gelf", "verify")

        self.headers = {
            'Content-Type': 'application/json'
        }
        self.hostname = os.uname()[1]

    def stop(self):
        pass

    def write(self, logentry):
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del logentry[i]

        self.gelf_message = {
            'version': '1.1',
            'host': self.hostname,
            'timestamp': time.time(),
            'short_message': json.dumps(logentry),
            'level': 1,
        }

        if 'False' in self.tls:
            self.gelf = requests.post(
                self.url,
                headers=self.headers,
                data=json.dumps(self.gelf_message)
            )
        else:
            self.gelf = requests.post(
                self.url,
                verify=self.verify,
                cert=(self.cert, self.cert_key),
                headers=self.headers,
                data=json.dumps(self.gelf_message)
            )
