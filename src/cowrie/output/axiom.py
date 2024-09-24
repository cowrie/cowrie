# Simple Telegram Bot logger

import json

from twisted.internet import defer
from twisted.python import log
from twisted.web import http_headers

import treq

import cowrie.core.output
from cowrie.core.config import CowrieConfig


AXIOM_URL = "https://api.axiom.co/v1"


class Output(cowrie.core.output.Output):
    """
    axiom.co output
    """

    def start(self) -> None:
        self.api_token = CowrieConfig.get("output_axiom", "api_token")
        self.dataset = CowrieConfig.get("output_axiom", "dataset")
        self.headers = http_headers.Headers(
            {
                b"Content-Type": [b"application/json"],
                b"Authorization": [f"Bearer {self.api_token}".encode()],
            }
        )
        self.url = f"{AXIOM_URL}/datasets/{self.dataset}/ingest"

    def stop(self) -> None:
        pass

    @defer.inlineCallbacks
    def write(self, event):
        event["_time"] = event.pop("timestamp")
        for i in list(event.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_") or i == "time" or i == "system":
                del event[i]

        try:
            msg = json.dumps(event, separators=(",", ":")).encode()
        except TypeError:
            log.err("jsonlog: Can't serialize: '" + repr(event) + "'")

        resp = yield treq.post(
            self.url,
            data=b"[" + msg + b"]",
            headers=self.headers,
        )

        if resp.code != 200:
            error = yield resp.text()
            log.err("jsonlog: Can't submit to Axiom: '" + repr(error) + "'")
