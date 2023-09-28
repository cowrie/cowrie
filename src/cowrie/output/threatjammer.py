# Copyright 2022 by GOODDATA LABS SL
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Cowrie plugin for reporting login attempts via the ThreatJammer.com Report API.
"ThreatJammer.com is a tool to track and detect attacks" <https://threatjammer.com>
"""


__author__ = "Diego Parrilla Santamaria"
__version__ = "0.1.0"

import datetime
from typing import Optional
from collections.abc import Generator

from treq import post

from twisted.internet import defer
from twisted.python import log
from twisted.web import http

from cowrie.core import output
from cowrie.core.config import CowrieConfig

# Buffer flush frequency (in minutes)
BUFFER_FLUSH_FREQUENCY: int = 1

# Buffer flush max size
BUFFER_FLUSH_MAX_SIZE: int = 1000

# API URL
THREATJAMMER_REPORT_URL: str = "https://dublin.report.threatjammer.com/v1/ip"

# Default Time To Live (TTL) in the ThreatJammer.com private blocklist. In minutes.
THREATJAMMER_DEFAULT_TTL: int = 86400

# Default category to store the ip address.
THREATJAMMER_DEFAULT_CATEGORY: str = "ABUSE"

# Track the login event
THREATJAMMER_DEFAULT_TRACK_LOGIN: bool = True

# Track the session event
THREATJAMMER_DEFAULT_TRACK_SESSION: bool = False

# Default tags to store the ip address.
THREATJAMMER_DEFAULT_TAGS: str = "COWRIE"


class HTTPClient:
    """
    HTTP client to report the IP adress set
    """

    def __init__(self, api_url: str, bearer_token: str):
        self.headers = {
            "User-Agent": "Cowrie Honeypot ThreatJammer.com output plugin",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
        }
        self.api_url = api_url

    def report(
        self,
        ip_set: set[str],
        category: str,
        ttl: int = 0,
        tags: Optional[list[str]] = None,
    ) -> None:
        payload: dict = {
            "addresses": list(ip_set),
            "type": category,
            "ttl": ttl,
            "tags": tags,
        }
        self._post(payload)

    @defer.inlineCallbacks
    def _post(self, payload: dict) -> Generator:
        try:
            response = yield post(
                url=self.api_url,
                headers=self.headers,
                json=payload,
            )

        except Exception as e:
            log.msg(
                eventid="cowrie.threatjammer.reportfail",
                format="ThreatJammer.com output plugin failed when reporting the payload %(payload)s. "
                "Exception raised: %(exception)s.",
                payload=str(payload),
                exception=repr(e),
            )
            return

        if response.code != http.ACCEPTED:
            reason = yield response.text()
            log.msg(
                eventid="cowrie.threatjammer.reportfail",
                format="ThreatJammer.com output plugin failed to report the payload %(payload)s. Returned the\
 HTTP status code %(response)s. Reason: %(reason)s.",
                payload=str(payload),
                response=response.code,
                reason=reason,
            )
        else:
            log.msg(
                eventid="cowrie.threatjammer.reportedipset",
                format="ThreatJammer.com output plugin successfully reported %(payload)s.",
                payload=str(payload),
            )
        return


class Output(output.Output):
    def start(self):
        self.api_url = CowrieConfig.get(
            "output_threatjammer",
            "api_url",
            fallback=THREATJAMMER_REPORT_URL,
        )
        self.default_ttl = CowrieConfig.getint(
            "output_threatjammer", "ttl", fallback=THREATJAMMER_DEFAULT_TTL
        )
        self.default_category = CowrieConfig.get(
            "output_threatjammer",
            "category",
            fallback=THREATJAMMER_DEFAULT_CATEGORY,
        )
        self.track_login = CowrieConfig.getboolean(
            "output_threatjammer",
            "track_login",
            fallback=THREATJAMMER_DEFAULT_TRACK_LOGIN,
        )
        self.track_session = CowrieConfig.getboolean(
            "output_threatjammer",
            "track_session",
            fallback=THREATJAMMER_DEFAULT_TRACK_SESSION,
        )
        self.bearer_token = CowrieConfig.get("output_threatjammer", "bearer_token")
        self.tags = CowrieConfig.get("output_threatjammer", "tags").split(",")

        self.last_report: int = -1
        self.report_bucket: int = BUFFER_FLUSH_MAX_SIZE
        self.ip_set: set[str] = set()

        self.track_events = []
        if self.track_login:
            self.track_events.append("cowrie.login")

        if self.track_session:
            self.track_events.append("cowrie.session")

        self.http_client = HTTPClient(self.api_url, self.bearer_token)
        log.msg(
            eventid="cowrie.threatjammer.reporterinitialized",
            format="ThreatJammer.com output plugin successfully initialized.\
 Category=%(category)s. TTL=%(ttl)s. Session Tracking=%(session_tracking)s. Login Tracking=%(login_tracking)s",
            category=self.default_category,
            ttl=self.default_ttl,
            session_tracking=self.track_session,
            login_tracking=self.track_login,
        )

    def stop(self):
        log.msg(
            eventid="cowrie.threatjammer.reporterterminated",
            format="ThreatJammer.com output plugin successfully terminated. Bye!",
        )

    def write(self, ev):
        if ev["eventid"].rsplit(".", 1)[0] in self.track_events:
            source_ip: str = ev["src_ip"]
            self.ip_set.add(source_ip)

            if self.last_report == -1:
                # Never execute in this cycle. Store timestamp of the first element.
                self.last_report = int(datetime.datetime.utcnow().timestamp())
            self.report_bucket -= 1
            if (
                self.report_bucket == 0
                or (int(datetime.datetime.utcnow().timestamp()) - self.last_report)
                > BUFFER_FLUSH_FREQUENCY * 60
            ):
                # Flush the ip_set if 1000 ips counted or more than 10 minutes since last flush
                self.http_client.report(
                    ip_set=self.ip_set,
                    category=self.default_category,
                    ttl=self.default_ttl,
                    tags=self.tags,
                )
                self.ip_set = set()
                self.report_bucket = BUFFER_FLUSH_MAX_SIZE
                self.last_report = -1
