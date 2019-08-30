"""
Cowrie Crashreport

This output plugin is not like the others. 
It has its own emit() function and does not use cowrie eventid's to avoid circular calls
"""

from __future__ import absolute_import, division

import json
import treq

from twisted.internet import defer, error
from twisted.python import log
from twisted.logger._levels import LogLevel

import cowrie.core.output
from cowrie.core.config import CowrieConfig
from cowrie._version import __version__

COWRIE_USER_AGENT = 'Cowrie Honeypot {}'.format(__version__)
COWRIE_URL = 'https://api.cowrie.org:8888/v1/'
COWRIE_URL = 'http://127.0.0.1:8888/v1/'

class Output(cowrie.core.output.Output):
    """
    Cowrie Crashreporter output
    """

    def start(self):
        """
        Start output plugin
        """
        self.apiKey = CowrieConfig().get('output_cowrie', 'api_key', fallback=None)
        self.debug = CowrieConfig().getboolean('output_cowrie', 'debug', fallback=False)

    def emit(self, event):
        """
        Note we override emit() here, unlike other plugins.
        """
        if event.get('log_level') == LogLevel.critical:
            self.crashreport(event)

    def stop(self):
        """
        Stop output plugin
        """
        pass

    def write(self, entry):
        """
        events are done in emit() not in write()
        """
        pass

    @defer.inlineCallbacks
    def crashreport(self, entry):
        """
        Crash report
        """
        resp = yield treq.post(COWRIE_URL, data={'crash': json.dumps(repr(entry))})
        content = yield resp.text()
        if self.debug:
            print("crashreport: "+content)
