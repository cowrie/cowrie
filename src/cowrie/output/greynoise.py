"""
Send attackers IP to GreyNoise
"""


import treq

from twisted.internet import defer, error
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

COWRIE_USER_AGENT = "Cowrie Honeypot"
GNAPI_URL = "https://api.greynoise.io/v3/community/"


class Output(cowrie.core.output.Output):
    """
    greynoise output
    """

    def start(self):
        """
        Start output plugin
        """
        self.apiKey = CowrieConfig().get("output_greynoise", "api_key", fallback=None)
        self.debug = CowrieConfig().getboolean(
            "output_greynoise", "debug", fallback=False
        )

    def stop(self):
        """
        Stop output plugin
        """
        pass

    def write(self, entry):
        if entry["eventid"] == "cowrie.session.connect":
            self.scanip(entry)

    @defer.inlineCallbacks
    def scanip(self, entry):
        """
        Scan IP against GreyNoise API
        """

        def message(query):
            if query["noise"]:
                log.msg(
                    eventid="cowrie.greynoise.result",
                    format="GreyNoise: %(IP) has been observed scanning the Internet. GreyNoise classification"
                           "is %(classification) and the believed owner is %(name)",
                    IP=query["ip"],
                    name=query["name"],
                    classification=query["classification"],
                )
            if query["riot"]:
                log.msg(
                    eventid="cowrie.greynoise.result",
                    format="GreyNoise: %(IP) belongs to a benign service or provider. The owner is %(name).",
                    IP=query["ip"],
                    name=query["name"],
                )

        gnUrl = f"{GNAPI_URL}{entry['src_ip']}".encode("utf8")
        headers = {"User-Agent": [COWRIE_USER_AGENT],
                   "key": self.apiKey}

        try:
            response = yield treq.get(
                url=gnUrl, headers=headers, timeout=10
            )
        except (
            defer.CancelledError,
            error.ConnectingCancelledError,
            error.DNSLookupError,
        ):
            log.msg("GreyNoise requests timeout")
            return

        if response.code != 200:
            rsp = yield response.text()
            log.error(f"greynoise: got error {rsp}")
            return

        j = yield response.json()
        if self.debug:
            log.msg("greynoise: debug: " + repr(j))

        if j["message"] == "Success":
            message(query)
        else:
            log.msg("greynoise: no results for for IP {}".format(entry["src_ip"]))
