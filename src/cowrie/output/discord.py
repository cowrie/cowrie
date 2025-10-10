"""
Simple Discord webhook logger
"""

from __future__ import annotations

import json

from io import BytesIO
from twisted.internet import reactor
from twisted.web import client, http_headers
from twisted.web.client import FileBodyProducer

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    def start(self) -> None:
        self.url = CowrieConfig.get("output_discord", "url").encode("utf8")
        self.agent = client.Agent(reactor)

    def stop(self) -> None:
        pass

    def write(self, event):
        webhook_message = "__New event__\n"

        for i in list(event.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]
            else:
                webhook_message += f"{i}: `{event[i]}`\n"

        self.postentry({"content": webhook_message})

    def postentry(self, entry):
        headers = http_headers.Headers(
            {
                b"Content-Type": [b"application/json"],
            }
        )

        body = FileBodyProducer(BytesIO(json.dumps(entry).encode("utf8")))
        self.agent.request(b"POST", self.url, headers, body)
