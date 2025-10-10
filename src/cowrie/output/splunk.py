# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>

"""
Splunk HTTP Event Collector (HEC) Connector.
Not ready for production use.
JSON log file is still recommended way to go
"""

from __future__ import annotations

import json
from io import BytesIO
from typing import Any

from zope.interface import implementer

from twisted.internet import reactor, ssl
from twisted.python import log
from twisted.web import client, http_headers
from twisted.web.client import FileBodyProducer
from twisted.web.iweb import IPolicyForHTTPS

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    Splunk HEC output
    """

    token: str
    agent: Any
    url: bytes

    def start(self) -> None:
        self.token = CowrieConfig.get("output_splunk", "token")
        self.url = CowrieConfig.get("output_splunk", "url").encode("utf8")
        self.index = CowrieConfig.get("output_splunk", "index", fallback="main")
        self.source = CowrieConfig.get("output_splunk", "source", fallback="cowrie")
        self.sourcetype = CowrieConfig.get(
            "output_splunk", "sourcetype", fallback="cowrie"
        )
        self.host = CowrieConfig.get("output_splunk", "host", fallback=None)
        contextFactory = WhitelistContextFactory()
        self.agent = client.Agent(reactor, contextFactory)

    def stop(self) -> None:
        pass

    def write(self, event):
        for i in list(event.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        splunkentry = {}
        if self.index:
            splunkentry["index"] = self.index
        if self.source:
            splunkentry["source"] = self.source
        if self.sourcetype:
            splunkentry["sourcetype"] = self.sourcetype
        if self.host:
            splunkentry["host"] = self.host
        else:
            splunkentry["host"] = event["sensor"]
        splunkentry["event"] = event
        self.postentry(splunkentry)

    def postentry(self, entry):
        """
        Send a JSON log entry to Splunk with Twisted
        """
        headers = http_headers.Headers(
            {
                b"User-Agent": [b"Cowrie SSH Honeypot"],
                b"Authorization": [b"Splunk " + self.token.encode("utf8")],
                b"Content-Type": [b"application/json"],
            }
        )
        body = FileBodyProducer(BytesIO(json.dumps(entry).encode("utf8")))
        d = self.agent.request(b"POST", self.url, headers, body)

        def cbBody(body):
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            failure.printTraceback()
            return processResult(failure.value.response)

        def cbResponse(response):
            if response.code == 200:
                return
            else:
                log.msg(f"SplunkHEC response: {response.code} {response.phrase}")
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d

        def cbError(failure):
            failure.printTraceback()

        def processResult(result):
            j = json.loads(result)
            log.msg("SplunkHEC response: {}".format(j["text"]))

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


@implementer(IPolicyForHTTPS)
class WhitelistContextFactory:
    def creatorForNetloc(self, hostname, port):
        return ssl.CertificateOptions(verify=False)
