# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The csirtg output plugin reads its token when it starts, and submits
# ABOUTME: one indicator per source IP and transport a day, keyed on protocol.

from __future__ import annotations

import importlib
import os
import sys
import types
import unittest
from typing import Any
from unittest.mock import Mock, patch

from cowrie.test.configoverride import override_option

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

try:
    import csirtgsdk  # noqa: F401
except ImportError:
    # The SDK is an optional dependency; stub it so the plugin imports.
    _sdk = types.ModuleType("csirtgsdk")
    _sdk.indicator = types.SimpleNamespace(Indicator=Mock)  # type: ignore[attr-defined]
    sys.modules["csirtgsdk"] = _sdk

SECTION = "output_csirtg"


def _import() -> types.ModuleType:
    sys.modules.pop("cowrie.output.csirtg", None)
    return importlib.import_module("cowrie.output.csirtg")


def _configure(test: unittest.TestCase, token: str) -> None:
    """Give the plugin a complete section and keep CSIRTG_TOKEN as it was."""
    for option, value in {
        "token": token,
        "username": "user",
        "feed": "feed",
        "description": "cowrie",
    }.items():
        override_option(test, SECTION, option, value)
    old_token = os.environ.get("CSIRTG_TOKEN")
    if old_token is None:
        test.addCleanup(os.environ.pop, "CSIRTG_TOKEN", None)
    else:
        test.addCleanup(os.environ.__setitem__, "CSIRTG_TOKEN", old_token)


def _connect(src_ip: str, protocol: str | None) -> dict[str, Any]:
    event: dict[str, Any] = {
        "eventid": "cowrie.session.connect",
        "session": "abc123",
        "src_ip": src_ip,
        "src_port": 55555,
        "timestamp": "2026-10-15T10:00:00.000000Z",
    }
    if protocol is not None:
        event["protocol"] = protocol
    return event


class CsirtgConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        _configure(self, "a1b2c3d4")

    def test_import_without_token_does_not_exit(self) -> None:
        """Only an enabled plugin needs a token; importing the module must
        not end the process."""
        _import()

    def test_placeholder_token_raises_instead_of_exiting(self) -> None:
        """load_plugins skips a plugin whose start() raises, but a SystemExit
        would end the honeypot; a missing token must be an ordinary error."""
        csirtg = _import()

        with self.assertRaises(ValueError):
            csirtg.Output()

    def test_start_uses_token_set_after_import(self) -> None:
        csirtg = _import()
        override_option(self, SECTION, "token", "token-after-import")

        csirtg.Output()

        self.assertEqual(os.environ["CSIRTG_TOKEN"], "token-after-import")


class CsirtgSubmitTests(unittest.TestCase):
    def setUp(self) -> None:
        _configure(self, "test-token")
        self.out = _import().Output()

    def _submit(self, *events: dict[str, Any]) -> list[dict[str, Any]]:
        """Run events through write() and return the indicators submitted."""
        indicator = Mock()
        indicator.return_value.submit.return_value = {"location": "https://x/1"}
        with patch.object(self.out.csirtgsdk.indicator, "Indicator", indicator):
            for event in events:
                self.out.write(event)
        return [c.args[0] for c in indicator.call_args_list]

    def test_ssh_connect_is_submitted_as_an_ssh_scanner(self) -> None:
        submitted = self._submit(_connect("1.2.3.4", "ssh"))
        self.assertEqual(len(submitted), 1)
        self.assertEqual(submitted[0]["indicator"], "1.2.3.4")
        self.assertEqual(submitted[0]["portlist"], 22)
        self.assertEqual(submitted[0]["tags"], "scanner,ssh")

    def test_telnet_connect_is_submitted_as_a_telnet_scanner(self) -> None:
        submitted = self._submit(_connect("1.2.3.4", "telnet"))
        self.assertEqual(len(submitted), 1)
        self.assertEqual(submitted[0]["portlist"], 23)
        self.assertEqual(submitted[0]["tags"], "scanner,telnet")

    def test_same_ip_and_transport_is_submitted_once_a_day(self) -> None:
        submitted = self._submit(
            _connect("1.2.3.4", "ssh"),
            _connect("1.2.3.4", "ssh"),
            _connect("1.2.3.4", "telnet"),
        )
        self.assertEqual([i["portlist"] for i in submitted], [22, 23])

    def test_event_without_a_known_transport_is_ignored(self) -> None:
        self.assertEqual(self._submit(_connect("1.2.3.4", None)), [])


if __name__ == "__main__":
    unittest.main()
