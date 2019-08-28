"""
Cowrie Telemetry
"""

from __future__ import absolute_import, division

import treq

from twisted.internet import defer, error
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig
from cowrie._version import __version__

COWRIE_USER_AGENT = 'Cowrie Honeypot {}'.format(__version__)
COWRIE_URL = 'http://api.cowrie.org:8888/v1/'
COWRIE_URL = 'http://127.0.0.1:8888/v1/'


class Output(cowrie.core.output.Output):
    """
    Cowrie Telemetry output
    """

    def start(self):
        """
        Start output plugin
        """
        self.apiKey = CowrieConfig().get('output_cowrie', 'api_key', fallback=None)
        self.debug = CowrieConfig().getboolean('output_cowrie', 'debug', fallback=False)

    def stop(self):
        """
        Stop output plugin
        """
        pass

    def write(self, entry):
        if entry['eventid'] == "cowrie.session.connect":
            self.scanip(entry)

    @defer.inlineCallbacks
    def crashreport(self, entry):
        """
        Crash report
        """


    @defer.inlineCallbacks
    def scanip(self, entry):
        """
        Scan IP againt telemetry API
        """
        def message(query):
            log.msg(
                eventid='cowrie.telemetry.result',
                format='telemetry: Scan for %(IP)s with %(tag)s have %(conf)s confidence'
                ' along with the following %(meta)s metadata',
                IP=entry['src_ip'],
                tag=query['name'],
                conf=query['confidence'],
                meta=query['metadata']
            )

        cowrieUrl = '{0}query/ip'.format(COWRIE_URL).encode('utf8')
        headers = ({'User-Agent': [COWRIE_USER_AGENT]})
        fields = {'key': self.apiKey, 'ip': entry['src_ip']}

        try:
            response = yield treq.post(
                url=cowrieUrl,
                data=fields,
                headers=headers,
                timeout=10)
        except (defer.CancelledError, error.ConnectingCancelledError, error.DNSLookupError):
            log.error("telemetry request timeout")
            return

        if response.code != 200:
            rsp = yield response.text()
            log.error("telemetry: got error {}".format(rsp))
            return

        j = yield response.json()
        if self.debug:
            log.msg("telemetry: debug: "+repr(j))

        if j['status'] == "ok":
            if "all" not in self.tags:
                for query in j['records']:
                    if query['name'] in self.tags:
                        message(query)
            else:
                for query in j['records']:
                    message(query)
        else:
            log.msg("telemetry: no results for for IP {0}".format(entry['src_ip']))
