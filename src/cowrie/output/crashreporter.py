"""
Cowrie Crashreport
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

"""
from twisted.logger._levels import LogLevel

def analyze(event):
    if event.get("log_level") == LogLevel.critical:
        print "Stopping for: ", event
        reactor.stop()

globalLogPublisher.addObserver(analyze)
"""


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
