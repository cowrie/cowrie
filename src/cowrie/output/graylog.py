"""
Simple Graylog HTTP Graylog Extended Log Format (GELF) logger.
"""

from __future__ import annotations

import json
import time

from io import BytesIO
from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.web import client, http_headers
from twisted.web.client import FileBodyProducer

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    def start(self) -> None:
        self.url = CowrieConfig.get("output_graylog", "url").encode("utf8")
        contextFactory = WebClientContextFactory()
        self.agent = client.Agent(reactor, contextFactory)

    def stop(self) -> None:
        pass

    def write(self, logentry):
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del logentry[i]

        gelf_message = {
            "version": "1.1",
            "host": logentry["sensor"],
            "timestamp": time.time(),
            "short_message": json.dumps(logentry),
            "level": 1,
        }

        self.postentry(gelf_message)

    def postentry(self, entry):
        headers = http_headers.Headers(
            {
                b"Content-Type": [b"application/json"],
            }
        )

        body = FileBodyProducer(BytesIO(json.dumps(entry).encode("utf8")))
        self.agent.request(b"POST", self.url, headers, body)


class WebClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)
