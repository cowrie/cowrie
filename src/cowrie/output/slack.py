# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from __future__ import annotations

import json
import time
from typing import Any

from slack import WebClient

import cowrie.core.output
from cowrie.core.config import CowrieConfig
from twisted.python import log


class Output(cowrie.core.output.Output):
    """
    slack output
    """

    def start(self) -> None:
        self.name = "slack output engine"
        self.slack_channel = CowrieConfig.get("output_slack", "channel")
        self.slack_token = CowrieConfig.get("output_slack", "token")
        self.simplified = CowrieConfig.getboolean(
            "output_slack", "simplified", fallback=False
        )
        self.show_timestamp = not CowrieConfig.getboolean(
            "output_slack", "timestamp", fallback=True
        )
        self.verbose = CowrieConfig.getboolean("output_slack", "verbose", fallback=True)
        if not self.show_timestamp and not self.simplified:
            log.msg(
                f"{self.name}: setting 'timestamp=false' is only effective when "
                + "'simplified' mode is enabled, this will be ignored."
            )

    def stop(self) -> None:
        pass

    def _format_simplified_message(self, event: dict[str, Any]) -> str:
        """
        Format event into a simplified, readable message with Slack formatting
        """
        if not self.show_timestamp:
            timestamp = ""
        else:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S") + " "

        logon_types = {
            "HoneyPotSSHTransport": "SSH",
            "cowrie.ssh": "SSH",
            "HTTP": "HTTP",
            "CowrieTelnetTransport": "Telnet",
            "cowrie.telnet": "Telnet",
        }
        logon_type = next(
            (
                logon_types[ltype]
                for ltype in logon_types
                if ltype in event.get("system", "")
            ),
            "XXX",
        )

        session = event.get("session", "unknown")
        src_ip = event.get("src_ip", "unknown")
        eventid = event.get("eventid", "unknown")

        base_msg = f"{timestamp}[{logon_type}_{session}] `{src_ip}` "

        # Helper function for command formatting
        def _format_command(cmd: str) -> str:
            cmd = cmd.strip()
            if "\n" in cmd or "\r" in cmd:
                return f"*MULTILINE CMD* : :arrow_down_small: ```{cmd}```"
            return f"*CMD* : :arrow_forward: `{cmd}`"

        def _format_download(event: dict[str, Any]) -> str:
            if event.get("url", "") == "":
                return f"*FILE* : :page_facing_up: Created file `{event.get('destfile', 'unknown')}` (SHA: `{event.get('shasum', 'unknown')}`)"
            return f"*FILE* : :inbox_tray: Downloaded URL `{event.get('url', 'unknown')}` to local file (SHA: `{event.get('shasum', 'unknown')}`)"

        # Dictionary of event handlers
        event_handlers = {
            "cowrie.client.connect": lambda: f":large_green_circle: *CONNECT* :large_green_circle: New {event.get('protocol', '').upper()} "
            + f"connection `{event.get('src_ip', 'unknown')}`, port: `{event.get('src_port', 'unknown')}`",
            "cowrie.session.connect": lambda: f":large_green_circle: *CONNECT* :large_green_circle: New {event.get('protocol', '').upper()} "
            + f"connection `{event.get('src_ip', 'unknown')}`, port: `{event.get('src_port', 'unknown')}`",
            "cowrie.login.success": lambda: f"*LOGIN* : :unlock: *SUCCESS* (`{event.get('username', 'unknown')}`:"
            + f"`{event.get('password', event.get('key', 'unknown'))}`)",
            "cowrie.login.failed": lambda: f"*LOGIN* : :lock: *FAILED* (`{event.get('username', 'unknown')}`:"
            + f"`{event.get('password', event.get('key', 'unknown'))}`)",
            "cowrie.client.fingerprint": lambda: f"*FINGERPRINT* : :bust_in_silhouette: `{event.get('username', 'unknown')}` | "
            + f":gear: `{event.get('type', 'unknown')}` | :key: `{event.get('fingerprint', 'unknown')}`",
            "cowrie.client.version": lambda: f"*CLIENT* : :gear: Version `{event.get('version', 'unknown')}`",
            "cowrie.client.kex": lambda: f"*KEX Config* : :level_slider: Algorithm `{event.get('kexAlgs', 'unknown')}`"
            + f"(Hassh = `{event.get('hassh', 'unknown')}`)",
            "cowrie.session.closed": lambda: ":red_circle: *LOGOUT* :red_circle: Session closed - "
            + f"Total duration: `{event.get('duration', 'unknown')}` seconds",
            "cowrie.command.input": lambda: _format_command(event.get("input", "")),
            "cowrie.session.file_download": lambda: _format_download(event),
            "cowrie.session.file_upload": lambda: f"*FILE* : :outbox_tray: Uploaded file to `{event.get('filename', 'unknown')}` "
            + f"(SHA: `{event.get('shasum', 'unknown')}`)",
            "cowrie.direct-tcpip.request": lambda: f"*TCP* : :arrows_counterclockwise: `{event.get('src_ip', 'unknown')}:{event.get('src_port', '???')}` ->"
            + f" `{event.get('dst_ip', 'unknown')}:{event.get('dst_port', '???')}`",
            "cowrie.direct-tcpip.data": lambda: f"*TCP* : :no_entry: Blocked direct-tcp forward request to `{event.get('dst_ip', 'unknown')}:"
            + f"{event.get('dst_port', '???')}` with {len(event.get('data', ''))} bytes of data",
            "cowrie.command.failed": lambda: f"*CMD* : :arrow_right_hook: *Failed* `{event.get('input', 'unknown')}` > "
            + f"`{event.get('message', 'unknown')}`",
            "cowrie.session.file_download_failed": lambda: f"*FILE* : :x: *Download Failed* `{event.get('message', 'unknown')}`",
            "cowrie.session.file_upload_failed": lambda: f"*FILE* : :x: *Upload Failed* `{event.get('message', 'unknown')}`",
        }

        # Check if we have a handler for this event
        if eventid in event_handlers:
            return f"{base_msg}{event_handlers[eventid]()}"

        # For other events, include the eventid and important details
        details: list[str] = []
        for key in (
            "input",
            "message",
            "username",
            "password",
            "url",
            "filename",
            "fname",
            "type",
            "fingerprint",
            "duration",
            "outfile",
            "shasum",
            "src_ip",
            "src_port",
        ):
            if event.get(key):
                details.append(f"{key}: `{event[key]}`")

        if details:
            return f"{base_msg}*{eventid.upper().replace('.', '_')}* : {' | '.join(details)}"
        elif self.verbose:
            return f"{base_msg}*{eventid.upper().replace('.', '_')}* : Event occurred"
        return ""

    def write(self, event: dict[str, Any]) -> None:
        for i in list(event.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        self.sc = WebClient(self.slack_token)

        # Check for verbose events to skip in case of not verbose mode
        verbose_events = (
            "cowrie.client.kex",
            "cowrie.client.connect",
            "cowrie.client.size",
            "cowrie.client.var",
            "cowrie.log.closed",
            "cowrie.log.opened",
            "cowrie.session.params",
        )
        eventid = event.get("eventid", "")
        if not self.verbose:
            if (eventid in verbose_events) or (
                eventid == "cowrie.command.input" and event.get("input", "") == ""
            ):
                return

        if self.simplified:
            message = self._format_simplified_message(event)
        else:
            # Original JSON format for backward compatibility
            message = "{} {}".format(
                time.strftime("%Y-%m-%d %H:%M:%S"),
                json.dumps(event, indent=4, sort_keys=True),
            )

        self.sc.chat_postMessage(
            channel=self.slack_channel,
            text=message,
        )
