# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>

"""
Splunk HTTP Event Collector (HEC) Connector.
Not ready for production use.
JSON log file is still recommended way to go
"""

from __future__ import division, absolute_import

from StringIO import StringIO

import json

from twisted.python import log
from twisted.internet import reactor
from twisted.web import client, http_headers
from twisted.web.client import FileBodyProducer
from twisted.internet.ssl import ClientContextFactory

import cowrie.core.output

from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):
    """
    """

    def __init__(self):
        """
        Required: token, url
        Optional: index, sourcetype, source, host
        """
        self.token = CONFIG.get('output_splunk', 'token')
        self.url = bytes(CONFIG.get('output_splunk', 'url'))
        try:
            self.index = CONFIG.get('output_splunk', 'index')
        except:
            self.index = None
        try:
            self.source = CONFIG.get('output_splunk', 'source')
        except:
            self.source = None
        try:
            self.sourcetype = CONFIG.get('output_splunk', 'sourcetype')
        except:
            self.sourcetype = None
        try:
            self.host = CONFIG.get('output_splunk', 'host')
        except:
            self.host = None

        cowrie.core.output.Output.__init__(self)


    def start(self):
        """
        """
        contextFactory = WebClientContextFactory()
        self.agent = client.Agent(reactor, contextFactory)


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
            splunkentry["host"] = logentry["sensor"]
        splunkentry["event"] = logentry
        self.postentry(splunkentry)


    def postentry(self, entry):
        """
        Send a JSON log entry to Splunk with Twisted
        """
        headers = http_headers.Headers({
            'User-Agent': ['Cowrie SSH Honeypot'],
            'Authorization': ["Splunk " + self.token],
            'Content-Type': ["application/json"]
        })
        body = FileBodyProducer(StringIO(json.dumps(entry)))
        d = self.agent.request('POST', self.url, headers, body)

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
                log.msg("SplunkHEC response: {} {}".format(response.code, response.phrase))
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



class WebClientContextFactory(ClientContextFactory):
    """
    """
    def getContext(self, hostname, port):
        """
        """
        return ClientContextFactory.getContext(self)


