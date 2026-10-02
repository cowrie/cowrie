# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for output plugin loading: which plugins are handed to the
# ABOUTME: dispatcher, and which ones are wired into reactor shutdown.

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from twisted.logger import ILogObserver, Logger, LogLevel
from zope.interface import implementer

import cowrie.core.output as output_module
from cowrie.core.output import Output, load_plugins


@implementer(ILogObserver)
class CaptureObserver:
    """Holds the log events a test provokes, instead of printing them."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def __call__(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class PluginStartFailed(Exception):
    def __init__(self) -> None:
        super().__init__("no api_key configured")


class DependencyMissing(ImportError):
    def __init__(self) -> None:
        super().__init__("No module named 'hpfeeds'")


class StubPlugin(Output):
    resource: str

    def start(self) -> None:
        self.resource = "acquired"

    def stop(self) -> None:
        self.resource = "released"

    def write(self, event: dict[str, Any]) -> None:
        pass


class BrokenPlugin(Output):
    """A plugin that fails to start, as one with incomplete config does.

    Its stop() touches what start() would have set up, the way hpfeeds3
    and abuseipdb do -- so calling it after a failed start raises.
    """

    resource: str

    def start(self) -> None:
        raise PluginStartFailed

    def stop(self) -> None:
        self.resource = self.resource.upper()

    def write(self, event: dict[str, Any]) -> None:
        pass


class FakeReactor:
    def __init__(self) -> None:
        self.triggers: list[tuple[str, str, Any]] = []

    def addSystemEventTrigger(self, phase: str, event: str, trigger: Any) -> None:
        self.triggers.append((phase, event, trigger))

    def fire_shutdown(self) -> None:
        for phase, event, trigger in self.triggers:
            if (phase, event) == ("after", "shutdown"):
                trigger()


class FakeConfig:
    """Enough of CowrieConfig for the loader and the Output base class."""

    def __init__(self, **enabled: bool) -> None:
        self.enabled = enabled

    def sections(self) -> list[str]:
        return ["honeypot", "ssh", *(f"output_{name}" for name in self.enabled)]

    def getboolean(self, section: str, option: str, fallback: bool = False) -> bool:
        if option == "enabled":
            return self.enabled[section.removeprefix("output_")]
        return fallback

    def get(self, section: str, option: str, fallback: Any = None) -> Any:
        return fallback


class LoadPluginsTests(unittest.TestCase):
    def setUp(self) -> None:
        # The loader's own diagnostics, captured rather than printed: two
        # of these tests provoke a load failure on purpose.
        self.observer = CaptureObserver()
        self.log = Logger(observer=self.observer)

    def messages(self) -> list[str]:
        return [event["log_format"].format(**event) for event in self.observer.events]

    def failures(self) -> list[dict[str, Any]]:
        return [e for e in self.observer.events if e["log_level"] is LogLevel.critical]

    def load(self, config: FakeConfig, **modules: type[Output]) -> Any:
        """Run the loader against stub plugin modules and a fake reactor."""
        reactor = FakeReactor()
        engines = {
            f"cowrie.output.{name}": SimpleNamespace(Output=plugin)
            for name, plugin in modules.items()
        }
        with (
            patch.object(output_module, "CowrieConfig", config),
            patch.object(output_module, "import_module", engines.__getitem__),
        ):
            plugins = load_plugins(reactor, log=self.log)
        return plugins, reactor

    def test_enabled_plugin_is_loaded_and_stopped_at_shutdown(self) -> None:
        plugins, reactor = self.load(FakeConfig(stub=True), stub=StubPlugin)

        self.assertEqual([type(p) for p in plugins], [StubPlugin])
        self.assertEqual(plugins[0].resource, "acquired")
        self.assertEqual(self.messages(), ["Loaded output engine: stub"])
        self.assertEqual(self.failures(), [])

        # After teardown, not before: a plugin's stop() must not close its
        # resources until the final events of sessions torn down during
        # shutdown have been delivered.
        self.assertEqual(reactor.triggers, [("after", "shutdown", plugins[0].stop)])

        reactor.fire_shutdown()
        self.assertEqual(plugins[0].resource, "released")

    def test_disabled_plugin_is_not_loaded(self) -> None:
        plugins, reactor = self.load(FakeConfig(stub=False), stub=StubPlugin)

        self.assertEqual(plugins, [])
        self.assertEqual(reactor.triggers, [])

    def test_plugin_that_failed_to_start_is_never_stopped(self) -> None:
        """A plugin whose start() raised never acquired anything, so its
        stop() must not run at shutdown -- it would raise into reactor
        teardown reaching for what start() would have set up."""
        plugins, reactor = self.load(FakeConfig(broken=True), broken=BrokenPlugin)

        self.assertEqual(plugins, [])
        self.assertEqual(reactor.triggers, [])
        reactor.fire_shutdown()

        self.assertEqual(self.messages(), ["Failed to load output engine: broken"])
        self.assertEqual(
            [f["log_failure"].type for f in self.failures()], [PluginStartFailed]
        )

    def test_failing_plugin_does_not_stop_the_others_loading(self) -> None:
        plugins, reactor = self.load(
            FakeConfig(broken=True, stub=True),
            broken=BrokenPlugin,
            stub=StubPlugin,
        )

        self.assertEqual([type(p) for p in plugins], [StubPlugin])
        self.assertEqual(
            self.messages(),
            [
                "Failed to load output engine: broken",
                "Loaded output engine: stub",
            ],
        )

        reactor.fire_shutdown()
        self.assertEqual(plugins[0].resource, "released")

    def test_missing_dependency_is_reported_and_skipped(self) -> None:
        """A plugin whose third-party dependency is not installed is
        skipped with a hint, not fatal to the honeypot."""

        def raise_import_error(name: str) -> Any:
            raise DependencyMissing

        reactor = FakeReactor()
        with (
            patch.object(output_module, "CowrieConfig", FakeConfig(hpfeeds3=True)),
            patch.object(output_module, "import_module", raise_import_error),
        ):
            plugins = load_plugins(reactor, log=self.log)

        self.assertEqual(plugins, [])
        self.assertEqual(reactor.triggers, [])
        self.assertEqual(
            self.messages(),
            [
                "Failed to load output engine: hpfeeds3 due to ImportError",
                "Please install the dependencies for hpfeeds3 listed in"
                " requirements-output.txt",
            ],
        )
