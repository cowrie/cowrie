# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import abc
import socket
from os import environ
from typing import TYPE_CHECKING, Any

from twisted.internet import reactor

from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from cowrie.core.events import EventDispatcher

# Events:
#  cowrie.client.fingerprint
#  cowrie.client.size
#  cowrie.client.var
#  cowrie.client.version
#  cowrie.command.input
#  cowrie.command.failed
#  cowrie.command.success (deprecated)
#  cowrie.direct-tcpip.data
#  cowrie.direct-tcpip.request
#  cowrie.log.closed
#  cowrie.login.failed
#  cowrie.login.success
#  cowrie.session.closed
#  cowrie.session.connect
#  cowrie.session.file_download
#  cowrie.session.file_upload


# The time is available in two formats in each event, as key 'time'
# in epoch format and in key 'timestamp' as a ISO compliant string
# in UTC.


def convert(data):
    """
    This converts a nested dictionary with bytes in it to string
    """
    match data:
        case str():
            return data
        case dict():
            return {convert(key): convert(value) for key, value in data.items()}
        case list():
            return [convert(element) for element in data]
        case bytes():
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return repr(data)
        case _:
            return data


class Output(metaclass=abc.ABCMeta):
    """
    This is the abstract base class intended to be inherited by
    cowrie output plugins. Plugins require the mandatory
    methods: stop, start and write
    """

    # The event pipeline for plugins that emit enrichment events of their
    # own (virustotal, reversedns, ...), set by the application container.
    dispatcher: EventDispatcher | None = None

    def __init__(self) -> None:
        self.sensor: str = CowrieConfig.get(
            "honeypot", "sensor_name", fallback=socket.gethostname()
        )
        self.uuid: str = CowrieConfig.get("honeypot", "uuid", fallback="unknown")

        self.timeFormat: str
        # use Z for UTC (Zulu) time, it's shorter.
        if "TZ" in environ and environ["TZ"] == "UTC":
            self.timeFormat = "%Y-%m-%dT%H:%M:%S.%fZ"
        else:
            self.timeFormat = "%Y-%m-%dT%H:%M:%S.%f%z"

        # Stop only after reactor teardown, so the final events of sessions
        # closed during shutdown deliver before the sink's resources close.
        reactor.addSystemEventTrigger("after", "shutdown", self.stop)

        self.start()

    def dispatch(self, **event: Any) -> None:
        """Emit an enrichment event into the event pipeline, carrying
        whatever attribution (session, src_ip) the plugin has."""
        if self.dispatcher:
            self.dispatcher.dispatch(event)

    @abc.abstractmethod
    def start(self) -> None:
        """
        Abstract method to initialize output plugin
        """
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        """
        Abstract method to shut down output plugin
        """
        pass

    @abc.abstractmethod
    def write(self, event: dict[str, Any]) -> None:
        """
        Handle a general event within the output plugin
        """
        pass
