"""
Simple remote syslog plugin.
"""

import cowrie.core.output

import logging
import logging.handlers
import socket
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    def start(self):
        self.host = CowrieConfig.get(
            "output_remotesyslog", "host", fallback="127.0.0.1"
        )

        self.port = int(CowrieConfig.get("output_remotesyslog", "port", fallback="514"))

        protocol = CowrieConfig.get(
            "output_remotesyslog", "protocol", fallback="udp"
        ).lower()

        self.logger = logging.getLogger("cowrieLogger")

        self.handler = logging.handlers.SysLogHandler(
            address=(self.host, self.port),
            socktype=None if protocol == "udp" else socket.SOCK_STREAM,
        )

        self.logger.addHandler(self.handler)

    def stop(self):
        self.handler.flush()
        self.logger.removeHandler(self.handler)
        self.handler.close()

    def write(self, event):
        for i in list(event.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_") or i == "time" or i == "system":
                del event[i]

        self.logger.warning(repr(event) + "\n")
