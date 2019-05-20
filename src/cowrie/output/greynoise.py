"""
Send attackers IP to GreyNoise
"""

from __future__ import absolute_import, division

import treq

from twisted.internet import defer, error
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

COWRIE_USER_AGENT = 'Cowrie Honeypot'
GNAPI_URL = 'http://api.greynoise.io:8888/v1/'


class Output(cowrie.core.output.Output):
    """
    greynoise output
    """

    def start(self):
        """
        Start output plugin
        """
        self.apiKey = CowrieConfig().get('output_greynoise', 'api_key', fallback=None)
        self.tags = CowrieConfig().get('output_greynoise', 'tags', fallback="all").split(",")
        self.debug = CowrieConfig().getboolean('output_greynoise', 'debug', fallback=False)

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
        def message(query):
            log.msg(
                eventid='cowrie.greynoise.result',
                format='greynoise: Scan for %(IP)s with %(tag)s have %(conf)s confidence'
                ' along with the following %(meta)s metadata',
                IP=entry['src_ip'],
                tag=query['name'],
                conf=query['confidence'],
                meta=query['metadata']
            )

        gnUrl = '{0}query/ip'.format(GNAPI_URL).encode('utf8')
        headers = ({'User-Agent': [COWRIE_USER_AGENT]})
        fields = {'key': self.apiKey, 'ip': entry['src_ip']}

        try:
            response = yield treq.post(
                url=gnUrl,
                data=fields,
                headers=headers,
                timeout=10)
        except (defer.CancelledError, error.ConnectingCancelledError, error.DNSLookupError):
            log.msg("GreyNoise requests timeout")
            return

        if response.code != 200:
            rsp = yield response.text()
            log.error("greynoise: got error {}".format(rsp))
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
                    message(query)
        else:
            log.msg("greynoise: no results for for IP {0}".format(entry['src_ip']))
