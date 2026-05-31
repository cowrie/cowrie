# SPDX-FileCopyrightText: 2015 Adam Ringwood <adam@nexadmin.com>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Send SSH logins to SANS DShield.
See https://isc.sans.edu/ssh.html
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os

import treq
from twisted.internet import defer, error
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

HTTP_TIMEOUT = 10
VERSION = 20260506

SUBMIT_URL = b"https://www.dshield.org/submitapi/"
DEBUG_SUBMIT_URL = b"https://www.dshield.org/devsubmitapi/"


class Output(cowrie.core.output.Output):
    """
    dshield output
    """

    debug: bool = False
    userid: str
    batch_size: int
    batch: list
    session_state: dict[str, dict[str, str]]

    def start(self):
        self.auth_key = CowrieConfig.get("output_dshield", "auth_key")
        self.userid = CowrieConfig.get("output_dshield", "userid")
        self.batch_size = CowrieConfig.getint("output_dshield", "batch_size")
        self.debug = CowrieConfig.getboolean("output_dshield", "debug", fallback=False)
        self.batch = []  # This is used to store login attempts in batches
        # Per-session enrichment fields (lastcommand, hassh, banner). Keyed on
        # session id so concurrent sessions do not stomp each other's state.
        self.session_state = {}

        self._warn_if_legacy_auth_key()

    def _warn_if_legacy_auth_key(self) -> None:
        """
        The pre-2026 DShield API took a base64-encoded auth_key and decoded
        it before computing the HMAC. The current submitapi uses the key as
        a raw string. Warn loudly if the configured key still looks
        base64-encoded so an operator notices before submissions are
        silently rejected.
        """
        try:
            base64.b64decode(self.auth_key, validate=True)
        except (binascii.Error, ValueError):
            return
        if "=" in self.auth_key:
            log.msg(
                "dshield: auth_key looks base64-encoded but the current "
                "DShield submit API expects the raw key. Update your "
                "config if submissions are rejected."
            )

    def stop(self):
        pass

    def _state(self, session: str) -> dict[str, str]:
        state = self.session_state.get(session)
        if state is None:
            state = {"lastcommand": "", "hassh": "", "banner": ""}
            self.session_state[session] = state
        return state

    def write(self, event):
        eventid = event["eventid"]
        session = event.get("session", "")

        if eventid in ("cowrie.login.success", "cowrie.login.failed"):
            state = self._state(session)
            self.batch.append(
                {
                    "timestamp": int(event["time"]),
                    "source_ip": event["src_ip"],
                    "user": event["username"],
                    "password": event.get("password", ""),
                    "lastcommand": state["lastcommand"],
                    "hassh": state["hassh"],
                    "banner": state["banner"],
                }
            )
            if self.debug:
                log.msg(
                    f"dshield: log appended, batch size {len(self.batch)} max size {self.batch_size}"
                )

            if len(self.batch) >= self.batch_size:
                if self.debug:
                    log.msg("dshield: batch size reached, submitting")
                batch_to_send = self.batch
                self.submit_entries(batch_to_send)
                self.batch = []
        elif eventid == "cowrie.command.input":
            self._state(session)["lastcommand"] = event["input"]
        elif eventid == "cowrie.client.kex":
            self._state(session)["hassh"] = event["hassh"]
        elif eventid == "cowrie.client.version":
            self._state(session)["banner"] = event["version"]
        elif eventid == "cowrie.session.closed":
            self.session_state.pop(session, None)

    def transmission_error(self, batch):
        self.batch.extend(batch)
        if len(self.batch) > self.batch_size * 2:
            self.batch = self.batch[-self.batch_size :]

    @defer.inlineCallbacks
    def submit_entries(self, batch):
        """
        DShield logs are sent to the https://www.dshield.org/submitapi/ endpoint.
        For debugging, use https://www.dshield.org/devsubmitapi/.
        """
        url = DEBUG_SUBMIT_URL if self.debug else SUBMIT_URL
        if self.debug:
            log.msg(f"dshield: using debug url {url!r}")

        # Build authentication header
        nonce = base64.b64encode(os.urandom(8)).decode("ascii")
        digest = hmac.new(
            (nonce + str(self.userid)).encode("utf-8"),
            msg=self.auth_key.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        hash64 = base64.b64encode(digest).decode("ascii")
        auth_header = (
            f"ISC-HMAC-SHA256 Credentials={hash64} "
            f"Userid={self.userid} Nonce={nonce}"
        )
        if self.debug:
            log.msg(f"dshield: authentication header {auth_header}")

        payload = {
            "type": "cowrie",
            "logs": batch,
            "authheader": auth_header,
        }

        headers = {
            b"Content-Type": [b"application/json"],
            b"User-Agent": [f"Cowrie-{VERSION}".encode("ascii")],
            b"X-ISC-Authorization": [auth_header.encode("ascii")],
            b"X-ISC-LogType": [b"cowrie"],
        }

        if self.debug:
            log.msg(f"dshield: posting headers {headers!r}")
            log.msg(f"dshield: posting payload {payload!r}")

        try:
            response = yield treq.post(
                url=url,
                headers=headers,
                data=json.dumps(payload).encode("utf-8"),
                timeout=HTTP_TIMEOUT,
                allow_redirects=False,
            )
            body = yield response.text()
        except (
            defer.CancelledError,
            error.ConnectingCancelledError,
            error.DNSLookupError,
        ) as e:
            log.msg(f"dshield: request failed: {e}")
            self.transmission_error(batch)
            return
        except Exception as e:
            log.msg(f"dshield: request failed: {e}")
            self.transmission_error(batch)
            return

        if self.debug:
            log.msg(f"dshield: status code {response.code}")
            log.msg(f"dshield: response {body}")

        if 200 <= response.code < 300:
            log.msg(f"dshield: submit response {body}")
        else:
            log.msg(f"dshield: ERROR status {response.code}: {body}")
            self.transmission_error(batch)
