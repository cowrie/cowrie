"""
Send attackers IP to GreyNoise
"""

from __future__ import absolute_import, division

import json
from http import HTTPStatus

from twisted.internet import defer
from twisted.python import log
import treq

import cowrie.core.output
from cowrie.core.config import CONFIG

COWRIE_USER_AGENT = 'Cowrie Honeypot'
GNAPI_URL = 'http://api.greynoise.io:8888/v1/'


class Output(cowrie.core.output.Output):

    def __init__(self):
        self.apiKey = CONFIG.get('output_greynoise', 'api_key', fallback=None)
        self.tags = CONFIG.get('output_greynoise', 'tags', fallback="all").split(",")
        self.debug = CONFIG.getboolean('output_greynoise', 'debug', fallback=False)
        cowrie.core.output.Output.__init__(self)

    def start(self):
        """
        Start output plugin
        """

    def stop(self):
        """
        Stop output plugin
        """
        pass

    def write(self, entry):
        if entry['eventid'] == "cowrie.session.connect":
            self.scanip(entry)

    @defer.inlineCallbacks
    def scanip(self, entry):
        """
        Scan IP againt Greynoise API
        """

        gnUrl = '{0}query/ip'.format(GNAPI_URL).encode('utf8')
        headers = ({'User-Agent': [COWRIE_USER_AGENT],'Content-Type': [b'application/json']})
        fields = {'key': self.apiKey, 'ip': entry['src_ip']}

        response = yield treq.post(
            url=gnUrl,
            data=fields,
            headers=headers)

        if response.code != HTTPStatus.OK:
            message = yield response.text()
            log.error("greynoise: got error {}".format(message))
            return

        j = yield response.json()
        if self.debug:
            log.msg("greynoise: debug: "+repr(j))
            if j['status'] == "ok":
                if "all" not in self.tags:
                    for query in j['records']:
                        if query['name'] in self.tags:
                            message(query)
                else:
                    for query in j['records']:
                        log.msg(
                            eventid='cowrie.greynoise.result',
                            format='greynoise: Scan for %(IP)s with %(tag)s have %(conf)s confidence'
                            ' along with the following %(meta)s metadata',
                            IP=entry['src_ip'],
                            tag=query['name'],
                            conf=query['confidence'],
                            meta=query['metadata']
                        )
            else:
                log.msg("greynoise: no results for for IP {0}".format(entry['src_ip']))

