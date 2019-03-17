"""
Send attackers IP to GreyNoise
"""

from __future__ import absolute_import, division

import json

from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.python import log
from twisted.web import client, http_headers
from twisted.web.client import FileBodyProducer

import cowrie.core.output
from cowrie.core.config import CONFIG

try:
    from BytesIO import BytesIO
except ImportError:
    from io import BytesIO


COWRIE_USER_AGENT = 'Cowrie Honeypot'
GNAPI_URL = 'http://api.greynoise.io:8888/v1/'


class Output(cowrie.core.output.Output):

    def __init__(self):
        self.apiKey = CONFIG.get('output_greynoise', 'api_key', fallback=None)
        self.tags = CONFIG.get('output_greynoise', 'tags', fallback="all").split(",")
        cowrie.core.output.Output.__init__(self)

    def start(self):
        """
        Start output plugin
        """
        self.agent = client.Agent(reactor, WebClientContextFactory())

    def stop(self):
        """
        Stop output plugin
        """
        pass

    def write(self, entry):
        if entry['eventid'] == "cowrie.session.connect":
            self.scanip(entry)

    def scanip(self, entry):
        """Scan IP againt Greynoise API
        """
        gnUrl = '{0}query/ip'.format(GNAPI_URL).encode('utf8')
        headers = http_headers.Headers({'User-Agent': [COWRIE_USER_AGENT]})
        fields = {'key': self.apiKey, 'ip': entry['src_ip']}
        body = FileBodyProducer(BytesIO(json.dumps(fields).encode('utf8')))
        d = self.agent.request(b'POST', gnUrl, headers, body)

        def cbResponse(response):
            """
            Main response callback, checks HTTP response code
            """
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                return d
            else:
                log.msg("GN Request failed: {} {}".format(
                    response.code, response.phrase))
                return

        def cbBody(body):
            """
            Received body
            """
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)

        def cbError(failure):
            failure.printTraceback()

        def processResult(result):
            """
            Extract the information we need from the body
            """
            result = result.decode('utf8')
            j = json.loads(result)
            if j['status'] == "ok":
                if "all" not in self.tags:
                    for query in j['records']:
                        if query['name'] in self.tags:
                            message(query)
                else:
                    for query in j['records']:
                        message(query)
            else:
                log.msg("GreyNoise Status is Unknown for IP {0}".format(entry['src_ip']))

        def message(query):
            log.msg(
                eventid='cowrie.greynoise',
                format='Greynoise Scan for %(IP)% with %(tag)% have %(conf)% confidence'
                'along with the following %(meta)% metatdata',
                IP=entry['src_ip'],
                tag=query['name'],
                conf=query['confidence'],
                meta=query['metadata']
            )

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


class WebClientContextFactory(ClientContextFactory):

    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)
