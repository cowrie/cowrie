# SPDX-FileCopyrightText: 2024 Aryan Shastri <aryanshastri1306@gmail.com>
# SPDX-FileCopyrightText: 2024-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# Output plugin for Signal messenger notifications via signal-cli-rest-api.
# https://github.com/bbernhard/signal-cli-rest-api

from __future__ import annotations

import json

import treq
from twisted.python import log  # pylint: disable=no-name-in-module

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """Signal messenger output plugin."""

    def start(self) -> None:
        self.api_url = CowrieConfig.get("output_signal", "api_url").rstrip("/")
        self.sender = CowrieConfig.get("output_signal", "sender")
        recipients_raw = CowrieConfig.get("output_signal", "recipients")
        self.recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]

    def stop(self) -> None:
        # Nothing to clean up; treq requests are fire-and-forget
        pass

    def write(self, event: dict) -> None:
        log_keys = [k for k in event if k.startswith("log_")]
        for k in log_keys:
            del event[k]

        msgtxt = f"[Cowrie {event['sensor']}]\nEvent: {event['eventid']}\nSource: {event['src_ip']}\nSession: {event['session']}"

        if event["eventid"] == "cowrie.login.success":
            msgtxt += f"\nUsername: {event['username']}\nPassword: {event['password']}"
            self._send(msgtxt)
        elif event["eventid"] in ("cowrie.command.failed", "cowrie.command.input"):
            msgtxt += f"\nCommand: {event['input']}"
            self._send(msgtxt)
        elif event["eventid"] == "cowrie.session.file_download":
            msgtxt += f"\nUrl: {event.get('url', '')}"
            self._send(msgtxt)

    def _send(self, message: str) -> None:
        log.msg("Signal plugin sending notification")
        payload = json.dumps(
            {
                "number": self.sender,
                "recipients": self.recipients,
                "message": message,
            }
        ).encode("utf-8")
        d = treq.post(
            f"{self.api_url}/v2/send",
            data=payload,
            headers={b"Content-Type": [b"application/json"]},
            allow_redirects=False,
        )
        d.addErrback(log.err, "Signal plugin request failed")
