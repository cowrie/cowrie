"""
Cowrie Crashreport

This output plugin is not like the others.
It has its own emit() function and does not use cowrie eventid's
to avoid circular calls
"""
from __future__ import annotations


import json

import treq

from twisted.internet import defer
from twisted.logger._levels import LogLevel
from twisted.python import log

import cowrie.core.output
from cowrie._version import __version__
from cowrie.core.config import CowrieConfig

COWRIE_USER_AGENT = f"Cowrie Honeypot {__version__}".encode("ascii")
COWRIE_URL = "https://api.cowrie.org/v1/crash"


class Output(cowrie.core.output.Output):
    """
    Cowrie Crashreporter output
    """

    def start(self):
        """
        Start output plugin
        """
        self.apiKey = CowrieConfig.get("output_cowrie", "api_key", fallback=None)
        self.debug = CowrieConfig.getboolean("output_cowrie", "debug", fallback=False)

    def emit(self, event):
        """
        Note we override emit() here, unlike other plugins.
        """
        if event.get("log_level") == LogLevel.critical:
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
        try:
            r = yield treq.post(
                COWRIE_URL,
                json.dumps(
                    {"log_text": entry.get("log_text"), "system": entry.get("system")}
                ).encode("ascii"),
                headers={
                    b"Content-Type": [b"application/json"],
                    b"User-Agent": [COWRIE_USER_AGENT],
                },
            )
            content = yield r.text()
            if self.debug:
                log.msg("crashreport: " + content)
        except Exception as e:
            log.msg("crashreporter failed" + repr(e))
