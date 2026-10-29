# SPDX-FileCopyrightText: 2026 Jari Huttunen <jari.tapani.huttunen@gmail.com>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Submit captured files and indicators to AlienVault OTX.

Files are uploaded for static and sandbox analysis with
``/api/v1/indicators/submit_file``. Download URLs can be submitted with
``/api/v1/indicators/submit_url``, and the sample's SHA-256, the download
URL and the attacker's public IP are reported in one OTX pulse per UTC
day.

API documentation: https://otx.alienvault.com/assets/static/external_api.html
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
from typing import Any
from urllib.parse import urlparse

import treq
from twisted.internet import defer, error
from twisted.logger import Logger
from twisted.web.client import (
    FileBodyProducer,
    RequestGenerationFailed,
    RequestTransmissionFailed,
    ResponseFailed,
)

import cowrie.core.output
from cowrie.core.config import CowrieConfig

HTTP_TIMEOUT = 30
COWRIE_USER_AGENT = "Cowrie Honeypot"
JSON_CONTENT_TYPE = "application/json"

OTX_API = "https://otx.alienvault.com/api/v1"
SUBMIT_FILE = f"{OTX_API}/indicators/submit_file"
SUBMIT_URL = f"{OTX_API}/indicators/submit_url"
CREATE_PULSE = f"{OTX_API}/pulses/create"
PATCH_PULSE = f"{OTX_API}/pulses/{{}}"

# Persisted next to Cowrie's other state so a restart during the same UTC
# day appends to the pulse it already created instead of making another.
STATE_FILE = "otx_pulse.json"

# A file captured before the plugin started was already offered to OTX by
# the previous process; re-downloading it must not upload it again.
TIME_SINCE_FIRST_DOWNLOAD = datetime.timedelta(minutes=1)

# The file name is attacker-chosen and goes into a multipart header.
UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]")

# treq wraps a request timeout as ResponseNeverReceived([CancelledError]);
# unconsumed failures would escape write() as unhandled Deferred errors
# (issue #1711). The Request* wrappers carry failures that happen while the
# multipart body is generated or transmitted; DNSLookupError is an OSError.
REQUEST_FAILURES = (
    defer.CancelledError,
    error.ConnectingCancelledError,
    error.ConnectError,
    error.ConnectionClosed,
    RequestGenerationFailed,
    RequestTransmissionFailed,
    ResponseFailed,
    OSError,
)

FILE_EVENTS = ("cowrie.session.file_download", "cowrie.session.file_upload")


class Output(cowrie.core.output.Output):
    """
    AlienVault OTX output plugin
    """

    _log = Logger()

    api_key: str
    upload: bool
    submit_url: bool
    pulse: bool
    pulse_name: str
    public: bool
    tlp: str
    tags: list[str]
    group_ids: list[int]
    include_src_ip: bool
    include_url: bool
    debug: bool
    pulse_id: str | None
    pulse_date: datetime.date | None
    seen_sha256: set[str]
    seen_urls: set[str]
    _pulse_chain: defer.Deferred

    def start(self) -> None:
        """
        Start output plugin
        """
        self.api_key = CowrieConfig.get("output_otx", "api_key", fallback="")
        self.upload = CowrieConfig.getboolean("output_otx", "upload", fallback=True)
        self.submit_url = CowrieConfig.getboolean(
            "output_otx", "submit_url", fallback=True
        )
        self.pulse = CowrieConfig.getboolean("output_otx", "pulse", fallback=True)
        self.pulse_name = CowrieConfig.get(
            "output_otx", "pulse_name", fallback="Cowrie honeypot samples"
        )
        self.public = CowrieConfig.getboolean("output_otx", "public", fallback=True)
        self.tlp = CowrieConfig.get("output_otx", "tlp", fallback="white").lower()
        self.include_src_ip = CowrieConfig.getboolean(
            "output_otx", "include_src_ip", fallback=True
        )
        self.include_url = CowrieConfig.getboolean(
            "output_otx", "include_url", fallback=True
        )
        self.debug = CowrieConfig.getboolean("output_otx", "debug", fallback=False)

        tags = CowrieConfig.get("output_otx", "tags", fallback="cowrie,honeypot")
        self.tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        self.group_ids = self._parse_group_ids(
            CowrieConfig.get("output_otx", "group_ids", fallback="")
        )

        self.pulse_id = None
        self.pulse_date = None
        self._pulse_chain = defer.succeed(None)
        self.seen_sha256 = set()
        self.seen_urls = set()
        self._load_pulse_state()

        if not self.api_key:
            self._log.warn("otx: no api_key specified in [output_otx] section")

        if self.tlp in ("red", "amber") and self.public:
            self._log.warn(
                "otx: TLP {tlp} pulses cannot be public, forcing public = false",
                tlp=self.tlp,
            )
            self.public = False

    def stop(self) -> None:
        """
        Stop output plugin
        """

    def write(self, event: dict[str, Any]) -> None:
        eventid = event.get("eventid")
        if eventid not in FILE_EVENTS:
            return

        shasum = event.get("shasum", "")
        artifact = self._artifact(event)
        if not shasum or artifact is None:
            self._log.info("otx: no captured file for event {eventid}", eventid=eventid)
            return

        if self._is_new(shasum, artifact):
            self.seen_sha256.add(shasum)
            if self.upload:
                self._observe(self.submit_file(event, artifact), "file", event)
            if self.pulse:
                self.report_pulse(event)

        if self.submit_url and eventid == "cowrie.session.file_download":
            url = event.get("url")
            if url and url not in self.seen_urls:
                self.seen_urls.add(url)
                self._observe(self.post_url(event, url), "url", event)

    def _observe(
        self, request: defer.Deferred, action: str, event: dict[str, Any]
    ) -> None:
        """
        Consume a request Deferred at the point it is dropped.

        The handlers in REQUEST_FAILURES cover the expected network failures,
        but an unexpected exception must still be logged with its session
        context instead of surfacing later as "Unhandled error in Deferred".
        """
        request.addErrback(self._request_failed, action, event)

    def _request_failed(self, failure: Any, action: str, event: dict[str, Any]) -> None:
        self._log.failure(
            "otx: {action} request failed", failure=failure, action=action
        )
        extra: dict[str, Any] = {}
        if event.get("shasum"):
            extra["sha256"] = event["shasum"]
        if event.get("url"):
            extra["url"] = event["url"]
        self._report(event, action, "error", f"OTX {action} request failed", **extra)

    def _parse_group_ids(self, value: str) -> list[int]:
        group_ids = []
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                group_ids.append(int(item))
            except ValueError:
                self._log.warn("otx: ignoring invalid group id {group}", group=item)
        return group_ids

    def _artifact(self, event: dict[str, Any]) -> str | None:
        """
        Locate the captured file on disk.

        Download and SFTP events carry a full path in 'outfile', while SCP
        upload events put only the hash there.
        """
        shasum = event.get("shasum")
        if not shasum:
            return None

        candidates: list[str] = []
        outfile = event.get("outfile")
        if isinstance(outfile, str) and outfile:
            candidates.append(outfile)
        download_path = CowrieConfig.get(
            "honeypot", "download_path", fallback="var/lib/cowrie/downloads"
        )
        candidates.append(os.path.join(download_path, shasum))

        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
        return None

    def _is_new(self, shasum: str, artifact: str) -> bool:
        if shasum in self.seen_sha256:
            self._log.info("otx: {sha256} was already submitted", sha256=shasum)
            return False

        try:
            mtime = datetime.datetime.fromtimestamp(
                os.stat(artifact).st_mtime, datetime.UTC
            )
        except OSError as e:
            self._log.info("otx: cannot stat {path}: {error}", path=artifact, error=e)
            return False

        if mtime < datetime.datetime.now(datetime.UTC) - TIME_SINCE_FIRST_DOWNLOAD:
            self._log.info(
                "otx: {sha256} was captured before the plugin started", sha256=shasum
            )
            return False
        return True

    def _headers(
        self, content_type: str | None = None
    ) -> dict[str | bytes, str | bytes]:
        headers: dict[str | bytes, str | bytes] = {
            "X-OTX-API-KEY": self.api_key,
            "User-Agent": COWRIE_USER_AGENT,
            "Accept": JSON_CONTENT_TYPE,
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _filename(self, event: dict[str, Any]) -> str:
        if event.get("eventid") == "cowrie.session.file_upload":
            name = event.get("filename", "")
        else:
            name = urlparse(event.get("url", "")).path
        return self._safe_filename(name, event.get("shasum", "sample"))

    def _safe_filename(self, name: str, fallback: str) -> str:
        """
        Make an attacker-supplied name safe for a multipart header.
        """
        name = name.replace("\\", "/").rsplit("/", 1)[-1]
        name = UNSAFE_FILENAME_CHARS.sub("_", name)
        if name in ("", ".", ".."):
            return fallback
        return name[:255]

    def _parse_body(self, body: str) -> dict[str, Any]:
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _detail(self, body: str) -> str:
        parsed = self._parse_body(body)
        detail = parsed.get("detail") or parsed.get("status") or ""
        return str(detail)[:200]

    def _report(
        self,
        event: dict[str, Any],
        action: str,
        result: str,
        message: str,
        **extra: Any,
    ) -> None:
        self.dispatch(
            eventid="cowrie.otx.submitted",
            format=message,
            session=event.get("session"),
            src_ip=event.get("src_ip"),
            protocol=event.get("protocol"),
            action=action,
            result=result,
            **extra,
        )

    @defer.inlineCallbacks
    def submit_file(self, event: dict[str, Any], artifact: str) -> Any:
        """
        Upload a captured file for static and sandbox analysis.
        """
        try:
            with open(artifact, "rb") as upload:
                response = yield treq.post(
                    url=SUBMIT_FILE,
                    headers=self._headers(),
                    files={
                        "file": (
                            self._filename(event),
                            "application/octet-stream",
                            FileBodyProducer(upload),
                        )
                    },
                    timeout=HTTP_TIMEOUT,
                    allow_redirects=False,
                )
                body = yield response.text()
        except REQUEST_FAILURES as e:
            self._log.info("otx: file submission failed: {error}", error=e)
            self._report(
                event,
                "file",
                "error",
                "OTX file submission failed for %(sha256)s",
                sha256=event.get("shasum", ""),
            )
            return

        detail = self._detail(body)
        if 200 <= response.code < 300:
            self._log.info(
                "otx: submitted {sha256} for analysis", sha256=event.get("shasum", "")
            )
            self._report(
                event,
                "file",
                "success",
                "OTX file submission succeeded for %(sha256)s",
                sha256=event.get("shasum", ""),
                detail=detail,
            )
        else:
            self._log.error(
                "otx: file submission error {code}: {body}",
                code=response.code,
                body=body[:500],
            )
            self._report(
                event,
                "file",
                "error",
                "OTX file submission failed for %(sha256)s (HTTP %(http_status)s)",
                sha256=event.get("shasum", ""),
                http_status=response.code,
                detail=detail,
            )

    @defer.inlineCallbacks
    def post_url(self, event: dict[str, Any], url: str) -> Any:
        """
        Submit a download URL for analysis.
        """
        payload = json.dumps({"url": url}).encode("utf-8")
        try:
            response = yield treq.post(
                url=SUBMIT_URL,
                headers=self._headers(JSON_CONTENT_TYPE),
                data=payload,
                timeout=HTTP_TIMEOUT,
                allow_redirects=False,
            )
            body = yield response.text()
        except REQUEST_FAILURES as e:
            self._log.info("otx: URL submission failed: {error}", error=e)
            self._report(
                event,
                "url",
                "error",
                "OTX URL submission failed for %(url)s",
                url=url,
            )
            return

        detail = self._detail(body)
        if 200 <= response.code < 300:
            self._log.info("otx: submitted URL {url}", url=url)
            self._report(
                event,
                "url",
                "success",
                "OTX URL submission succeeded for %(url)s",
                url=url,
                detail=detail,
            )
        else:
            self._log.error(
                "otx: URL submission error {code}: {body}",
                code=response.code,
                body=body[:500],
            )
            self._report(
                event,
                "url",
                "error",
                "OTX URL submission failed for %(url)s (HTTP %(http_status)s)",
                url=url,
                http_status=response.code,
                detail=detail,
            )

    def _global_ip(
        self, value: Any
    ) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        if not value:
            return None
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None
        return address if address.is_global else None

    def _indicators(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        indicators: list[dict[str, Any]] = []
        shasum = event.get("shasum", "")
        if shasum:
            indicators.append(
                {
                    "indicator": shasum,
                    "type": "FileHash-SHA256",
                    "description": "Malware captured by a Cowrie honeypot",
                }
            )

        if self.include_url:
            url = event.get("url")
            if url and urlparse(url).scheme in ("http", "https") and len(url) <= 2000:
                indicators.append(
                    {
                        "indicator": url,
                        "type": "URL",
                        "description": "Download location of the captured malware",
                        "role": "malware_hosting",
                    }
                )

        if self.include_src_ip:
            address = self._global_ip(event.get("src_ip"))
            if address is not None:
                indicators.append(
                    {
                        "indicator": str(address),
                        "type": f"IPv{address.version}",
                        "description": "Source of the attack",
                        "role": "scanning_host",
                    }
                )
        return indicators

    def _pulse_name(self, day: datetime.date) -> str:
        prefix = self.pulse_name.strip() or "Cowrie honeypot samples"
        name = f"{prefix} {day.isoformat()}"
        if len(name) > 64:
            name = name[:64]
        if len(name) < 5:
            name = f"Cowrie {day.isoformat()}"
        return name

    def _pulse_description(self, event: dict[str, Any]) -> str:
        return (
            f"Malware and infrastructure captured by the Cowrie honeypot "
            f"'{self.sensor}' (session {event.get('session', 'unknown')}, "
            f"protocol {event.get('protocol', 'unknown')}, "
            f"source {event.get('src_ip', 'unknown')})."
        )

    def _pulse_payload(
        self, day: datetime.date, indicators: list[dict[str, Any]]
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self._pulse_name(day),
            "public": self.public,
            "TLP": self.tlp,
            "tags": self.tags,
            "indicators": indicators,
        }
        if self.group_ids:
            payload["group_ids"] = self.group_ids
        return payload

    def report_pulse(self, event: dict[str, Any]) -> None:
        """
        Report the sample's indicators in this UTC day's pulse.

        Pulse operations are serialized: two samples captured at the same
        time must not both create the day's pulse. The shared chain keeps its
        own error handler, so callers need not consume a result.
        """
        indicators = self._indicators(event)
        if not indicators:
            return

        def report(_: Any = None) -> defer.Deferred:
            today = datetime.datetime.now(datetime.UTC).date()
            if self.pulse_id and self.pulse_date == today:
                return self._patch_pulse(event, indicators)
            return self._create_pulse(event, today, indicators)

        self._pulse_chain = self._pulse_chain.addCallback(report)
        self._pulse_chain = self._pulse_chain.addErrback(self._pulse_failed)

    def _pulse_failed(self, failure: Any) -> None:
        self._log.failure("otx: pulse operation failed", failure=failure)

    @defer.inlineCallbacks
    def _create_pulse(
        self,
        event: dict[str, Any],
        day: datetime.date,
        indicators: list[dict[str, Any]],
    ) -> Any:
        payload = self._pulse_payload(day, indicators)
        payload["description"] = self._pulse_description(event)
        if self.debug:
            self._log.info("otx: creating pulse {payload!r}", payload=payload)

        try:
            response = yield treq.post(
                url=CREATE_PULSE,
                headers=self._headers(JSON_CONTENT_TYPE),
                data=json.dumps(payload).encode("utf-8"),
                timeout=HTTP_TIMEOUT,
                allow_redirects=False,
            )
            body = yield response.text()
        except REQUEST_FAILURES as e:
            self._log.info("otx: pulse creation failed: {error}", error=e)
            self._report(
                event,
                "pulse",
                "error",
                "OTX pulse creation failed for %(sha256)s",
                sha256=event.get("shasum", ""),
            )
            return

        detail = self._detail(body)
        if not 200 <= response.code < 300:
            self._log.error(
                "otx: pulse creation error {code}: {body}",
                code=response.code,
                body=body[:500],
            )
            self._report(
                event,
                "pulse",
                "error",
                "OTX pulse creation failed for %(sha256)s (HTTP %(http_status)s)",
                sha256=event.get("shasum", ""),
                http_status=response.code,
                detail=detail,
            )
            return

        pulse_id = self._parse_body(body).get("id")
        if not isinstance(pulse_id, str) or not pulse_id:
            self._log.error("otx: pulse created without an id: {body}", body=body[:500])
            self._report(
                event,
                "pulse",
                "error",
                "OTX pulse creation returned no pulse id for %(sha256)s",
                sha256=event.get("shasum", ""),
                detail=detail,
            )
            return

        self.pulse_id = pulse_id
        self.pulse_date = day
        self._save_pulse_state()
        self._log.info(
            "otx: created pulse {pulse_id} ({name})",
            pulse_id=pulse_id,
            name=payload["name"],
        )
        self._report(
            event,
            "pulse",
            "success",
            "OTX pulse %(pulse_id)s created",
            sha256=event.get("shasum", ""),
            pulse_id=pulse_id,
            detail=detail,
        )

    @defer.inlineCallbacks
    def _patch_pulse(
        self, event: dict[str, Any], indicators: list[dict[str, Any]]
    ) -> Any:
        pulse_id = self.pulse_id
        if not pulse_id:
            return
        payload = {"indicators": {"add": indicators}}
        if self.debug:
            self._log.info("otx: updating pulse {payload!r}", payload=payload)

        try:
            response = yield treq.patch(
                url=PATCH_PULSE.format(pulse_id),
                headers=self._headers(JSON_CONTENT_TYPE),
                data=json.dumps(payload).encode("utf-8"),
                timeout=HTTP_TIMEOUT,
                allow_redirects=False,
            )
            body = yield response.text()
        except REQUEST_FAILURES as e:
            self._log.info("otx: pulse update failed: {error}", error=e)
            self._report(
                event,
                "pulse",
                "error",
                "OTX pulse update failed for %(sha256)s",
                sha256=event.get("shasum", ""),
                pulse_id=pulse_id,
            )
            return

        detail = self._detail(body)
        if 200 <= response.code < 300:
            self._log.info("otx: updated pulse {pulse_id}", pulse_id=pulse_id)
            self._report(
                event,
                "pulse",
                "success",
                "OTX pulse %(pulse_id)s updated",
                sha256=event.get("shasum", ""),
                pulse_id=pulse_id,
                detail=detail,
            )
        else:
            if response.code == 404:
                # The pulse was deleted; build a fresh one for the next sample.
                self.pulse_id = None
                self.pulse_date = None
                self._clear_pulse_state()
            self._log.error(
                "otx: pulse update error {code}: {body}",
                code=response.code,
                body=body[:500],
            )
            self._report(
                event,
                "pulse",
                "error",
                "OTX pulse update failed for %(sha256)s (HTTP %(http_status)s)",
                sha256=event.get("shasum", ""),
                pulse_id=pulse_id,
                http_status=response.code,
                detail=detail,
            )

    def _state_file(self) -> str:
        state_path = CowrieConfig.get("honeypot", "state_path", fallback=".")
        return os.path.join(state_path, STATE_FILE)

    def _load_pulse_state(self) -> None:
        try:
            with open(self._state_file(), encoding="utf-8") as state_file:
                state = json.load(state_file)
            day = datetime.date.fromisoformat(state["date"])
            pulse_id = state["pulse_id"]
        except (OSError, KeyError, TypeError, ValueError):
            return
        if (
            day == datetime.datetime.now(datetime.UTC).date()
            and isinstance(pulse_id, str)
            and pulse_id
        ):
            self.pulse_date = day
            self.pulse_id = pulse_id

    def _save_pulse_state(self) -> None:
        if not self.pulse_date or not self.pulse_id:
            return
        path = self._state_file()
        temporary = f"{path}.tmp"
        try:
            with open(temporary, "w", encoding="utf-8") as state_file:
                json.dump(
                    {"date": self.pulse_date.isoformat(), "pulse_id": self.pulse_id},
                    state_file,
                )
            os.replace(temporary, path)
        except OSError as e:
            self._log.info("otx: could not persist pulse state: {error}", error=e)

    def _clear_pulse_state(self) -> None:
        try:
            os.unlink(self._state_file())
        except OSError:
            pass
