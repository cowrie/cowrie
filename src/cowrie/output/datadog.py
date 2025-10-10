"""
Simple Datadog HTTP logger.
"""

from __future__ import annotations

import json
import platform

from io import BytesIO
from twisted.internet import reactor
from twisted.python import log
from twisted.web import client, http_headers
from twisted.web.client import FileBodyProducer

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    def start(self) -> None:
        self.url = CowrieConfig.get("output_datadog", "url").encode("utf8")
        self.api_key = CowrieConfig.get(
            "output_datadog", "api_key", fallback=""
        ).encode("utf8")
        if len(self.api_key) == 0:
            log.msg("Datadog output module: API key is not defined.")
        self.ddsource = CowrieConfig.get(
            "output_datadog", "ddsource", fallback="cowrie"
        )
        self.ddtags = CowrieConfig.get("output_datadog", "ddtags", fallback="env:dev")
        self.service = CowrieConfig.get(
            "output_datadog", "service", fallback="honeypot"
        )
        self.hostname = CowrieConfig.get(
            "output_datadog", "hostname", fallback=platform.node()
        )
        self.agent = client.Agent(reactor)

    def stop(self) -> None:
        pass

    def write(self, event):
        for i in list(event.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]
        message = [
            {
                "ddsource": self.ddsource,
                "ddtags": self.ddtags,
                "hostname": self.hostname,
                "message": json.dumps(event),
                "service": self.service,
            }
        ]
        self.postentry(message)

    def postentry(self, entry):
        base_headers = {
            b"Accept": [b"application/json"],
            b"Content-Type": [b"application/json"],
            b"DD-API-KEY": [self.api_key],
        }
        headers = http_headers.Headers(base_headers)
        body = FileBodyProducer(BytesIO(json.dumps(entry).encode("utf8")))
        self.agent.request(b"POST", self.url, headers, body)
