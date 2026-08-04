# SPDX-FileCopyrightText: 2016 Wes <wes@barely3am.com>
# SPDX-FileCopyrightText: 2016-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import os
import sys
from datetime import datetime

from twisted.logger import Logger

import cowrie.core.output
from cowrie.core.config import CowrieConfig

_log = Logger()

token = CowrieConfig.get("output_csirtg", "token", fallback="a1b2c3d4")
if token == "a1b2c3d4":
    _log.info("output_csirtg: token not found in configuration file")
    sys.exit(1)

os.environ["CSIRTG_TOKEN"] = token
import csirtgsdk  # noqa: E402


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
        system = e.get("system", None)

        if system not in [
            "cowrie.ssh.factory.CowrieSSHFactory",
            "cowrie.telnet.transport.HoneyPotTelnetFactory",
        ]:
            return

        today = str(datetime.now().date())

        if not self.context.get(today):
            self.context = {}
            self.context[today] = set()

        key = ",".join([peerIP, system])

        if key in self.context[today]:
            return

        self.context[today].add(key)

        tags = "scanner,ssh"
        port = 22
        if e["system"] == "cowrie.telnet.transport.HoneyPotTelnetFactory":
            tags = "scanner,telnet"
            port = 23

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

        ind = csirtgsdk.indicator.Indicator(i).submit()

        if self.debug is True:
            self._log.info("output_csirtg: Submitted {result!r} to CSIRTG", result=ind)

        self._log.info(
            "output_csirtg: submitted to csirtg at {location} ",
            location=ind["location"],
        )
