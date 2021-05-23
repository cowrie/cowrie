import os
from datetime import datetime

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

os.environ["CSIRTG_TOKEN"] = CowrieConfig.get("output_csirtg", "token")
import csirtgsdk  # noqa: E402


class Output(cowrie.core.output.Output):
    """
    CSIRTG output
    """
    def start(self):
        """
        Start the output module.
        Note that csirtsdk is imported here because it reads CSIRTG_TOKEN on import
        Cowrie sets this environment variable.
        """
        self.user = CowrieConfig.get("output_csirtg", "username")
        self.feed = CowrieConfig.get("output_csirtg", "feed")
        self.debug = CowrieConfig.get("output_csirtg", "debug", fallback=False)
        self.description = CowrieConfig.get("output_csirtg", "description")
        # token = CowrieConfig.get("output_csirtg", "token")
        # if token is None:
        #    log.msg("output_csirtg: token not found in configuration file")

        self.context = {}
        # self.client = csirtgsdk.client.Client()

    def stop(self):
        pass

    def write(self, e):
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
            log.msg(f"Submitting {i!r} to CSIRTG")

        # ret = csirtgsdk.indicator.Indicator(f"{self.user}/{self.feed}", i).submit()
        ret = csirtgsdk.indicator.Indicator(i).submit()

        if self.debug is True:
            log.msg(f"Submitted {ret!r} to CSIRTG")

        log.msg("output_csirtg: logged to csirtg {} ".format(ret["location"]))
