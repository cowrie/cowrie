# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import abc
import socket
from importlib import import_module
from os import environ
from typing import TYPE_CHECKING, Any

from twisted.logger import Logger

from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from cowrie.core.events import EventDispatcher

# ABOUTME: Base class for output plugins: config wiring, sensor naming, and
# ABOUTME: the write()/dispatch() contract every plugin implements. Also
# ABOUTME: loads the configured plugins and owns their lifecycle.
# The event ids and their attributes are documented in docs/OUTPUT.rst.

# The time is available in two formats in each event, as key 'time'
# in epoch format and in key 'timestamp' as a ISO compliant string
# in UTC.

_log = Logger()


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


def load_plugins(reactor: Any, log: Logger = _log) -> list[Output]:
    """
    Construct the output plugins enabled in the configuration.

    A plugin is wired into shutdown only once it has started: one whose
    start() raised never acquired the resources its stop() releases, and
    calling stop() on it would raise into reactor teardown. A plugin that
    cannot be loaded is skipped -- the honeypot runs without it rather
    than not at all.

    Plugins stop after reactor teardown, so the final events of sessions
    closed during shutdown deliver before a sink's resources close.

    ``log`` names the diagnostic emitter so tests can capture the
    load failures they provoke instead of printing them.
    """
    plugins: list[Output] = []

    for section in CowrieConfig.sections():
        if not section.startswith("output_"):
            continue
        if CowrieConfig.getboolean(section, "enabled", fallback=False) is False:
            continue

        engine: str = section.split("_")[1]
        try:
            plugin: Output = import_module(f"cowrie.output.{engine}").Output()
        except ImportError:
            log.failure(
                "Failed to load output engine: {engine} due to ImportError",
                engine=engine,
            )
            log.info(
                "Please install the dependencies for {engine} listed in requirements-output.txt",
                engine=engine,
            )
        except Exception:
            log.failure("Failed to load output engine: {engine}", engine=engine)
        else:
            plugins.append(plugin)
            reactor.addSystemEventTrigger("after", "shutdown", plugin.stop)
            log.info("Loaded output engine: {engine}", engine=engine)

    return plugins
