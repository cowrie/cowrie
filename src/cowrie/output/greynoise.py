# SPDX-FileCopyrightText: 2019 Mehtab Zafar <mehtab.zafar98@gmail.com>
# SPDX-FileCopyrightText: 2019-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Send attackers IP to GreyNoise
"""

from __future__ import annotations

import treq
from twisted.internet import defer, error
from twisted.logger import Logger

import cowrie.core.output
from cowrie.core.config import CowrieConfig

COWRIE_USER_AGENT = "Cowrie Honeypot"
GNAPI_URL = "https://api.greynoise.io/v3/community/"


class Output(cowrie.core.output.Output):
    """
    greynoise output
    """

    _log = Logger()

    def start(self):
        """
        Start output plugin
        """
        self.apiKey = CowrieConfig.get("output_greynoise", "api_key", fallback=None)
        self.debug = CowrieConfig.getboolean(
            "output_greynoise", "debug", fallback=False
        )

    def stop(self):
        """
        Stop output plugin
        """
        pass

    def write(self, event):
        if event["eventid"] == "cowrie.session.connect":
            self.scanip(event)

    @defer.inlineCallbacks
    def scanip(self, event):
        """
        Scan IP against GreyNoise API
        """

        def message(query):
            if query["noise"]:
                self.dispatch(
                    eventid="cowrie.greynoise.result",
                    session=event["session"],
                    src_ip=event["src_ip"],
                    protocol=event["protocol"],
                    format=f"GreyNoise: {query['ip']} has been observed scanning the Internet. GreyNoise "
                    f"classification is {query['classification']} and the believed owner is {query['name']}",
                )
            if query["riot"]:
                self.dispatch(
                    eventid="cowrie.greynoise.result",
                    session=event["session"],
                    src_ip=event["src_ip"],
                    protocol=event["protocol"],
                    format=f"GreyNoise: {query['ip']} belongs to a benign service or provider. "
                    f"The owner is {query['name']}.",
                )

        gn_url = f"{GNAPI_URL}{event['src_ip']}".encode()
        headers = {"User-Agent": [COWRIE_USER_AGENT], "key": self.apiKey}

        try:
            response = yield treq.get(
                url=gn_url, headers=headers, timeout=10, allow_redirects=False
            )
        except (
            defer.CancelledError,
            error.ConnectingCancelledError,
            error.DNSLookupError,
        ):
            self._log.info("GreyNoise requests timeout")
            return

        if response.code == 404:
            rsp = yield response.json()
            self._log.error("GreyNoise: {ip} - {msg}", ip=rsp["ip"], msg=rsp["message"])
            return

        if response.code != 200:
            rsp = yield response.text()
            self._log.error("GreyNoise: got error {response}", response=rsp)
            return

        j = yield response.json()
        if self.debug:
            self._log.info("GreyNoise: debug: {response!r}", response=j)

        if j["message"] == "Success":
            message(j)
        else:
            self._log.info(
                "GreyNoise: no results for for IP {src_ip}", src_ip=event["src_ip"]
            )
