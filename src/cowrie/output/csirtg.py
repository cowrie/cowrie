# SPDX-FileCopyrightText: 2016 Wes <wes@barely3am.com>
# SPDX-FileCopyrightText: 2016-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import os
from datetime import datetime

from twisted.logger import Logger

import cowrie.core.output
from cowrie.core.config import CowrieConfig

# The port and tags reported for each transport a session event names.
TRANSPORTS = {"ssh": (22, "scanner,ssh"), "telnet": (23, "scanner,telnet")}


class Output(cowrie.core.output.Output):
    """
    CSIRTG output
    """

    _log = Logger()

    def start(self):
        """
        Start the output module.
        Note that csirtsdk is imported here because it reads CSIRTG_TOKEN on import
        Cowrie sets this environment variable.
        """
        token = CowrieConfig.get("output_csirtg", "token", fallback="a1b2c3d4")
        if token == "a1b2c3d4":
            self._log.info("output_csirtg: token not found in configuration file")
            # An ordinary error lets load_plugins log and skip this plugin.
            raise ValueError
        os.environ["CSIRTG_TOKEN"] = token
        import csirtgsdk

        self.csirtgsdk = csirtgsdk
        self.user = CowrieConfig.get("output_csirtg", "username")
        self.feed = CowrieConfig.get("output_csirtg", "feed")
        self.debug = CowrieConfig.getboolean("output_csirtg", "debug", fallback=False)
        self.description = CowrieConfig.get("output_csirtg", "description")

        self.context = {}
        # self.client = csirtgsdk.client.Client()

    def stop(self):
        pass

    def write(self, event):
        """
        Only pass on connection events
        """
        if event["eventid"] == "cowrie.session.connect":
            self.submitIp(event)

    def submitIp(self, e):
        peerIP = e["src_ip"]
        ts = e["timestamp"]
        protocol = e.get("protocol")

        if protocol not in TRANSPORTS:
            return

        today = str(datetime.now().date())

        if not self.context.get(today):
            self.context = {}
            self.context[today] = set()

        key = ",".join([peerIP, protocol])

        if key in self.context[today]:
            return

        self.context[today].add(key)

        port, tags = TRANSPORTS[protocol]

        i = {
            "user": self.user,
            "feed": self.feed,
            "indicator": peerIP,
            "portlist": port,
            "protocol": "tcp",
            "tags": tags,
            "firsttime": ts,
            "lasttime": ts,
            "description": self.description,
        }

        if self.debug is True:
            self._log.info(
                "output_csirtg: Submitting {indicator!r} to CSIRTG", indicator=i
            )

        ind = self.csirtgsdk.indicator.Indicator(i).submit()

        if self.debug is True:
            self._log.info("output_csirtg: Submitted {result!r} to CSIRTG", result=ind)

        self._log.info(
            "output_csirtg: submitted to csirtg at {location} ",
            location=ind["location"],
        )
