# SPDX-FileCopyrightText: 2026 Jari Huttunen <jari.tapani.huttunen@gmail.com>
## SPDX-FileCopyrightText: 2017-2026 Michel Oosterhof <michel@oosterhof.net>

# SPDX-License-Identifier: BSD-3-Clause

"""
Submit malware URLs to URLhaus.
See https://urlhaus.abuse.ch/api/
"""

from __future__ import annotations

import json

import treq
from twisted.internet import defer, error
from twisted.logger import Logger
from twisted.web.client import ResponseFailed

import cowrie.core.output
from cowrie.core.config import CowrieConfig

HTTP_TIMEOUT = 15
COWRIE_USER_AGENT = "Cowrie Honeypot"

SUBMIT_URL = b"https://urlhaus.abuse.ch/api/"


class Output(cowrie.core.output.Output):
    """
    urlhaus output
    """

    _log = Logger()

    api_key: str
    anonymous: str
    tags: list[str]
    submitted_urls: set[str]

    def start(self):
        """
        Start output plugin
        """
        self.api_key = CowrieConfig.get("output_urlhaus", "api_key", fallback="")
        self.anonymous = CowrieConfig.get("output_urlhaus", "anonymous", fallback="0")
        tags = CowrieConfig.get("output_urlhaus", "tags", fallback="cowrie,honeypot")
        self.tags = [t.strip() for t in tags.split(",") if t.strip()]
        self.submitted_urls = set()

        if not self.api_key:
            self._log.warn("urlhaus: no api_key specified in [output_urlhaus] section")

    def stop(self):
        """
        Stop output plugin
        """
        pass

    def write(self, event):
        if event["eventid"] != "cowrie.session.file_download":
            return

        url = event.get("url")
        if not url or url in self.submitted_urls:
            return

        self.submitted_urls.add(url)
        self.submit(event)

    @defer.inlineCallbacks
    def submit(self, event):
        """
        Submit a URL to URLhaus
        """
        url = event["url"]

        payload = {
            "anonymous": self.anonymous,
            "submission": [
                {"url": url, "threat": "malware_download", "tags": self.tags}
            ],
        }
        headers = {
            b"Content-Type": [b"application/json"],
            b"Auth-Key": [self.api_key.encode("utf-8")],
            b"User-Agent": [COWRIE_USER_AGENT.encode("ascii")],
        }

        try:
            response = yield treq.post(
                url=SUBMIT_URL,
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
            ResponseFailed,
        ) as e:
            # ResponseFailed (its subclass ResponseNeverReceived wraps the
            # CancelledError treq raises on a request timeout) would otherwise
            # escape as an unhandled Deferred error (issue #1711).
            self._log.info("urlhaus: request failed: {error}", error=e)
            self.dispatch(
                eventid="cowrie.urlhaus.submitted",
                format="URLhaus submission failed for URL: %(url)s",
                session=event["session"],
                src_ip=event["src_ip"],
                url=url,
                result="error",
            )
            return

        if 200 <= response.code < 300:
            self._log.info("urlhaus: submitted {url}", url=url)
            self.dispatch(
                eventid="cowrie.urlhaus.submitted",
                format="URLhaus submission succeeded for URL: %(url)s",
                session=event["session"],
                src_ip=event["src_ip"],
                url=url,
                result="success",
            )
        else:
            self._log.error(
                "urlhaus: error status {code}: {body}", code=response.code, body=body
            )
            self.dispatch(
                eventid="cowrie.urlhaus.submitted",
                format="URLhaus submission failed for URL: %(url)s (HTTP %(http_status)s)",
                session=event["session"],
                src_ip=event["src_ip"],
                url=url,
                result="error",
                http_status=response.code,
            )
