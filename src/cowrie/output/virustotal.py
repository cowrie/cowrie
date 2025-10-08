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

"""
Send SSH logins to VirusTotal using v3 API
"""

from __future__ import annotations

import base64
import datetime
import json
import os
from typing import Any, TYPE_CHECKING
from urllib.parse import urlencode, urlparse

if TYPE_CHECKING:
    from collections.abc import Callable

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet import reactor
from twisted.python import log
from twisted.web import client, http_headers
from twisted.web.iweb import IBodyProducer, IResponse

import cowrie.core.output
from cowrie.core.config import CowrieConfig


COWRIE_USER_AGENT = "Cowrie Honeypot"
VTAPI_URL = "https://www.virustotal.com/api/v3/"
COMMENT = "First seen by #Cowrie SSH/telnet Honeypot http://github.com/cowrie/cowrie"
TIME_SINCE_FIRST_DOWNLOAD = datetime.timedelta(minutes=1)


def readBody(response: IResponse) -> defer.Deferred:
    """
    Read response body with proper handling to avoid deprecation warnings.
    This is a wrapper around client.readBody that ensures compatibility.
    """
    from twisted.internet.protocol import Protocol

    d: defer.Deferred = defer.Deferred()

    class BodyCollector(Protocol):
        def __init__(self):
            self.data = b""

        def dataReceived(self, data):
            self.data += data

        def connectionLost(self, reason):
            d.callback(self.data)

    collector = BodyCollector()
    response.deliverBody(collector)
    return d


class Output(cowrie.core.output.Output):
    """
    virustotal output
    """

    apiKey: str
    debug: bool = False
    commenttext: str
    agent: Any
    scan_url: bool
    scan_file: bool
    url_cache: dict[str, datetime.datetime]  # url and last time succesfully submitted
    collection_name: str | None = None
    collection_id: str | None = None

    def start(self) -> None:
        """
        Start output plugin
        """
        self.url_cache = {}

        self.apiKey = CowrieConfig.get("output_virustotal", "api_key")
        self.debug = CowrieConfig.getboolean(
            "output_virustotal", "debug", fallback=False
        )
        self.upload = CowrieConfig.getboolean(
            "output_virustotal", "upload", fallback=True
        )
        self.comment = CowrieConfig.getboolean(
            "output_virustotal", "comment", fallback=True
        )
        self.scan_file = CowrieConfig.getboolean(
            "output_virustotal", "scan_file", fallback=True
        )
        self.scan_url = CowrieConfig.getboolean(
            "output_virustotal", "scan_url", fallback=True
        )
        self.commenttext = CowrieConfig.get(
            "output_virustotal", "commenttext", fallback=COMMENT
        )
        self.collection_name = CowrieConfig.get(
            "output_virustotal", "collection", fallback=None
        )
        self.agent = client.Agent(reactor)

        # Initialize collection if configured
        if self.collection_name:
            self._init_collection()

    def stop(self) -> None:
        """
        Stop output plugin
        """

    def write(self, event: dict[str, Any]) -> None:
        if event["eventid"] == "cowrie.session.file_download":
            if self.scan_url and "url" in event:
                log.msg("Checking url scan report at VT")
                self.scanurl(event)
            if self._is_new_shasum(event["shasum"]) and self.scan_file:
                log.msg("Checking file scan report at VT")
                self.scanfile(event)

        elif event["eventid"] == "cowrie.session.file_upload":
            if self._is_new_shasum(event["shasum"]) and self.scan_file:
                log.msg("Checking file scan report at VT")
                self.scanfile(event)

    def _is_new_shasum(self, shasum):
        # Get the downloaded file's modification time
        shasumfile = os.path.join(CowrieConfig.get("honeypot", "download_path"), shasum)
        file_modification_time = datetime.datetime.fromtimestamp(
            os.stat(shasumfile).st_mtime
        )

        # Assumptions:
        # 1. A downloaded file that was already downloaded before is not written instead of the first downloaded file
        # 2. On that stage of the code, the file that needs to be scanned in VT is supposed to be downloaded already
        #
        # Check:
        # If the file was first downloaded more than a "period of time" (e.g 1 min) ago -
        # it has been apparently scanned before in VT and therefore is not going to be checked again
        if file_modification_time < datetime.datetime.now() - TIME_SINCE_FIRST_DOWNLOAD:
            log.msg(f"File with shasum '{shasum}' was downloaded before")
            return False
        return True

    def _build_headers(
        self, content_type: str | None = None, extra_headers: dict | None = None
    ) -> http_headers.Headers:
        """Build common HTTP headers for VT API requests"""
        headers_dict = {
            "User-Agent": [COWRIE_USER_AGENT],
            "x-apikey": [self.apiKey],
        }
        if content_type:
            headers_dict["Content-Type"] = [content_type]
        if extra_headers:
            headers_dict.update(extra_headers)
        return http_headers.Headers(headers_dict)

    def _make_request(
        self,
        method: bytes,
        url: bytes,
        headers: http_headers.Headers,
        body: IBodyProducer | None = None,
        process_response: Callable | None = None,
        valid_codes: list[int] | None = None,
        error_prefix: str = "VT request",
    ) -> defer.Deferred[Any]:
        """
        Make an HTTP request with standard error handling

        Args:
            method: HTTP method (GET, POST, etc)
            url: Full URL to request
            headers: HTTP headers
            body: Optional request body
            process_response: Callback to process successful response body
            valid_codes: List of valid HTTP response codes (default: [200])
            error_prefix: Prefix for error messages
        """
        if valid_codes is None:
            valid_codes = [200]

        d = self.agent.request(method, url, headers, body)

        def cbResponse(response):
            if response.code in valid_codes:
                d = readBody(response)
                if process_response:
                    d.addCallback(process_response)
                return d
            else:
                log.msg(f"{error_prefix} failed: {response.code} {response.phrase}")

        def cbError(failure):
            log.msg(f"{error_prefix} error")
            failure.printTraceback()

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d  # type: ignore[no-any-return]

    def _parse_scan_results(
        self, last_analysis_results: dict
    ) -> dict[str, dict[str, str]]:
        """Parse scan results into standardized format"""
        scans_summary: dict[str, dict[str, str]] = {}
        for engine, result in last_analysis_results.items():
            engine_key = engine.lower()
            scans_summary[engine_key] = {
                "detected": str(
                    result.get("category") in ["malicious", "suspicious"]
                ).lower(),
                "result": str(result.get("result", "")).lower(),
            }
        return scans_summary

    def scanfile(self, event):
        """
        Check file scan report for a hash
        Argument is full event so we can access full file later on
        """
        vtUrl = f"{VTAPI_URL}files/{event['shasum']}".encode()
        headers = self._build_headers()

        def process_response(body_bytes):
            if self.debug:
                log.msg(f"VT scanfile result: {body_bytes}")
            result = body_bytes.decode("utf8")
            j = json.loads(result)

            # Check for errors in v3 API response
            if "error" in j:
                if j["error"]["code"] == "NotFoundError":
                    log.msg("VT: New file - not found in database")
                    log.msg(
                        eventid="cowrie.virustotal.scanfile",
                        format="VT: New file %(sha256)s",
                        session=event["session"],
                        sha256=event["shasum"],
                        is_new="true",
                    )

                    try:
                        b = os.path.basename(urlparse(event["url"]).path)
                        fileName = b if b else event["shasum"]
                    except KeyError:
                        fileName = event["shasum"]

                    if self.upload:
                        return self.postfile(event["outfile"], fileName)
                else:
                    log.msg(
                        f"VT: Error - {j['error']['code']}: {j['error']['message']}"
                    )
                return

            # Process successful response with file data
            if "data" in j:
                data = j["data"]
                attributes = data.get("attributes", {})

                # Extract scan results
                last_analysis_results = attributes.get("last_analysis_results", {})
                stats = attributes.get("last_analysis_stats", {})

                log.msg("VT: File found in database")
                scans_summary = self._parse_scan_results(last_analysis_results)

                malicious_count = stats.get("malicious", 0)
                total_count = sum(stats.values())
                scan_date = attributes.get("last_analysis_date", "unknown")

                log.msg(
                    eventid="cowrie.virustotal.scanfile",
                    format="VT: Binary file with sha256 %(sha256)s was found malicious "
                    "by %(positives)s out of %(total)s feeds (scanned on %(scan_date)s)",
                    session=event["session"],
                    positives=malicious_count,
                    total=total_count,
                    scan_date=scan_date,
                    sha256=event["shasum"],
                    scans=scans_summary,
                    is_new="false",
                )
                log.msg(
                    f"VT: permalink: https://www.virustotal.com/gui/file/{event['shasum']}"
                )
            else:
                log.msg("VT: unexpected response format")

        return self._make_request(
            b"GET",
            vtUrl,
            headers,
            process_response=process_response,
            valid_codes=[200, 404],
            error_prefix="VT scanfile",
        )

    def postfile(self, artifact, fileName):
        """
        Send a file to VirusTotal
        """
        vtUrl = f"{VTAPI_URL}files".encode()
        fields = {}  # v3 API doesn't need apikey in form data
        with open(artifact, "rb") as f:
            files = {("file", fileName, f)}
            if self.debug:
                log.msg(f"submitting to VT: {files!r}")
            contentType, body = encode_multipart_formdata(fields, files)
        producer = StringProducer(body)
        headers = self._build_headers(
            content_type=contentType.decode("utf-8"), extra_headers={"Accept": ["*/*"]}
        )

        def process_response(body_bytes):
            if self.debug:
                log.msg(f"VT postfile result: {body_bytes}")
            result = body_bytes.decode("utf8")
            j = json.loads(result)

            # Check for errors in v3 API response
            if "error" in j:
                log.msg(
                    f"VT: Upload error - {j['error']['code']}: {j['error']['message']}"
                )
                return

            # Process successful upload response
            if "data" in j:
                data = j["data"]
                file_id = data.get("id")
                if file_id:
                    log.msg("VT: File uploaded successfully")
                    # Add to collection if enabled
                    if self.collection_name:
                        self._add_to_collection("files", file_id, f"file {file_id}")
                    # Post comment if enabled
                    if self.comment:
                        return self._post_comment("files", file_id, "Comment")
                else:
                    log.msg("VT: Upload successful but no file ID returned")
            else:
                log.msg("VT: unexpected upload response format")

        return self._make_request(
            b"POST",
            vtUrl,
            headers,
            body=producer,
            process_response=process_response,
            error_prefix="VT postfile",
        )

    def scanurl(self, event):
        """
        Check url scan report for a hash
        """
        if event["url"] in self.url_cache:
            log.msg(
                f"output_virustotal: url {event['url']} was already successfully submitted"
            )
            return

        # First submit the URL for scanning, then get the report
        # v3 API requires URL to be base64 encoded with padding removed
        url_id = base64.urlsafe_b64encode(event["url"].encode()).decode().rstrip("=")

        vtUrl = f"{VTAPI_URL}urls/{url_id}".encode()
        headers = self._build_headers()

        def process_response(body_bytes):
            if self.debug:
                log.msg(f"VT scanurl result: {body_bytes}")
            if body_bytes == b"[]\n":
                log.err(f"VT scanurl did not return results: {body_bytes}")
                return
            result = body_bytes.decode("utf8")
            j = json.loads(result)

            # we got a status=200 assume it was successfully submitted
            self.url_cache[event["url"]] = datetime.datetime.now()

            # Check for errors in v3 API response
            if "error" in j:
                if j["error"]["code"] == "NotFoundError":
                    log.msg("VT: New URL - not found in database")
                    log.msg(
                        eventid="cowrie.virustotal.scanurl",
                        format="VT: New URL %(url)s",
                        session=event["session"],
                        url=event["url"],
                        is_new="true",
                    )
                    # Submit URL for scanning
                    return self.submiturl(event)
                else:
                    log.msg(
                        f"VT: Error - {j['error']['code']}: {j['error']['message']}"
                    )
                return

            # Process successful response with URL data
            if "data" in j:
                data = j["data"]
                attributes = data.get("attributes", {})

                # Check if URL has been scanned
                last_analysis_results = attributes.get("last_analysis_results", {})
                if not last_analysis_results:
                    log.msg("VT: URL was submitted but has not yet been scanned")
                    return

                stats = attributes.get("last_analysis_stats", {})

                log.msg("VT: URL has been scanned before")
                scans_summary = self._parse_scan_results(last_analysis_results)

                malicious_count = stats.get("malicious", 0)
                total_count = sum(stats.values())
                scan_date = attributes.get("last_analysis_date", "unknown")

                log.msg(
                    eventid="cowrie.virustotal.scanurl",
                    format="VT: URL %(url)s was found malicious by "
                    "%(positives)s out of %(total)s feeds (scanned on %(scan_date)s)",
                    session=event["session"],
                    positives=malicious_count,
                    total=total_count,
                    scan_date=scan_date,
                    url=event["url"],
                    scans=scans_summary,
                    is_new="false",
                )
                log.msg(f"VT: permalink: https://www.virustotal.com/gui/url/{url_id}")
            else:
                log.msg("VT: unexpected response format")

        d = self._make_request(
            b"GET",
            vtUrl,
            headers,
            process_response=process_response,
            error_prefix="VT scanurl",
        )
        if d:
            # Log success message on successful response
            d.addCallback(
                lambda _: log.msg("VT scanurl successful: 200 OK")
                if _ is not None
                else None
            )
        return d

    def submiturl(self, event):
        """
        Submit a URL for scanning in VirusTotal v3 API
        """
        vtUrl = f"{VTAPI_URL}urls".encode()
        headers = self._build_headers(content_type="application/x-www-form-urlencoded")
        body = StringProducer(urlencode({"url": event["url"]}).encode("utf-8"))

        def process_response(body_bytes):
            if self.debug:
                log.msg(f"VT submiturl result: {body_bytes}")
            result = body_bytes.decode("utf8")
            j = json.loads(result)

            # Check for errors in v3 API response
            if "error" in j:
                log.msg(
                    f"VT: URL submission error - {j['error']['code']}: {j['error']['message']}"
                )
                return

            # Process successful submission response
            if "data" in j:
                data = j["data"]
                url_id = data.get("id")
                if url_id:
                    log.msg("VT: URL submitted successfully for scanning")
                    # Add to collection if enabled
                    if self.collection_name:
                        self._add_to_collection("urls", url_id, f"URL {url_id}")
                    # Post comment if enabled (this is a new URL submission)
                    if self.comment:
                        return self._post_comment("urls", url_id, "URL comment")
                else:
                    log.msg("VT: URL submission successful but no ID returned")
            else:
                log.msg("VT: unexpected URL submission response format")

        return self._make_request(
            b"POST",
            vtUrl,
            headers,
            body=body,
            process_response=process_response,
            error_prefix="VT submiturl",
        )

    def _post_comment(
        self, resource_type: str, resource_id: str, comment_type: str
    ) -> defer.Deferred:
        """
        Send a comment to VirusTotal for a file or URL

        Args:
            resource_type: 'files' or 'urls'
            resource_id: The file hash or URL ID
            comment_type: Description for logging ('Comment' or 'URL comment')
        """
        vtUrl = f"{VTAPI_URL}{resource_type}/{resource_id}/comments".encode()
        comment_data = {
            "data": {"type": "comment", "attributes": {"text": self.commenttext}}
        }
        headers = self._build_headers(content_type="application/json")
        body = StringProducer(json.dumps(comment_data).encode("utf-8"))

        def process_response(body_bytes):
            if self.debug:
                log.msg(f"VT post{comment_type.lower()} result: {body_bytes}")
            result = body_bytes.decode("utf8")
            j = json.loads(result)

            # Check for errors in v3 API response
            if "error" in j:
                log.msg(
                    f"VT: {comment_type} error - {j['error']['code']}: {j['error']['message']}"
                )
                return False

            # Process successful comment response
            if "data" in j:
                log.msg(f"VT: {comment_type} posted successfully")
                return True
            else:
                log.msg(f"VT: unexpected {comment_type.lower()} response format")
                return False

        return self._make_request(
            b"POST",
            vtUrl,
            headers,
            body=body,
            process_response=process_response,
            error_prefix=f"VT post{comment_type.lower()}",
        )

    def _init_collection(self) -> None:
        """
        Initialize collection - create if doesn't exist or get ID if exists
        This is called during start() if collection is configured
        """
        # Try to create the collection (it's idempotent - won't duplicate if exists)
        vtUrl = f"{VTAPI_URL}collections".encode()
        collection_data = {
            "data": {
                "type": "collection",
                "attributes": {
                    "name": self.collection_name,
                    "description": f"Cowrie honeypot artifacts - {self.collection_name}",
                },
            }
        }
        headers = self._build_headers(content_type="application/json")
        body = StringProducer(json.dumps(collection_data).encode("utf-8"))

        def process_response(body_bytes):
            if self.debug:
                log.msg(f"VT create collection result: {body_bytes}")
            result = body_bytes.decode("utf8")
            j = json.loads(result)

            # Check for errors in v3 API response
            if "error" in j:
                error_code = j["error"].get("code")
                # AlreadyExistsError means collection exists - that's OK
                if error_code == "AlreadyExistsError":
                    log.msg(
                        f"VT: Collection '{self.collection_name}' already exists - will use existing"
                    )
                    # We'll get the ID from the error details if available
                    # Otherwise we'll get it on first add operation
                else:
                    log.msg(
                        f"VT: Collection creation error - {j['error']['code']}: {j['error'].get('message', 'Unknown error')}"
                    )
                return

            # Process successful creation response
            if "data" in j:
                data = j["data"]
                collection_id = data.get("id")
                if collection_id:
                    self.collection_id = collection_id
                    log.msg(
                        f"VT: Collection '{self.collection_name}' created with ID: {collection_id}"
                    )
                else:
                    log.msg("VT: Collection created but no ID returned")
            else:
                log.msg("VT: unexpected collection creation response format")

        self._make_request(
            b"POST",
            vtUrl,
            headers,
            body=body,
            process_response=process_response,
            error_prefix="VT create collection",
        )

    def _add_to_collection(
        self, resource_type: str, resource_id: str, resource_descriptor: str
    ) -> defer.Deferred[Any]:
        """
        Add a file or URL to the configured collection

        Args:
            resource_type: 'files' or 'urls'
            resource_id: The file hash or URL ID
            resource_descriptor: Human-readable description for logging
        """
        if not self.collection_name or not self.collection_id:
            # Collection not configured or not initialized yet
            if self.debug and self.collection_name:
                log.msg(
                    f"VT: Cannot add {resource_descriptor} to collection - collection ID not yet available"
                )
            return defer.succeed(None)

        vtUrl = f"{VTAPI_URL}collections/{self.collection_id}/{resource_type}".encode()

        # Build the request based on resource type
        if resource_type == "files":
            item_data = {"type": "file", "id": resource_id}
        else:  # urls
            item_data = {"type": "url", "id": resource_id}

        headers = self._build_headers(content_type="application/json")
        body = StringProducer(json.dumps({"data": [item_data]}).encode("utf-8"))

        def process_response(body_bytes):
            if self.debug:
                log.msg(f"VT add to collection result: {body_bytes}")
            result = body_bytes.decode("utf8")
            j = json.loads(result)

            # Check for errors in v3 API response
            if "error" in j:
                log.msg(
                    f"VT: Add to collection error - {j['error']['code']}: {j['error'].get('message', 'Unknown error')}"
                )
                return False

            # Success
            log.msg(
                f"VT: Added {resource_descriptor} to collection '{self.collection_name}'"
            )
            return True

        return self._make_request(
            b"POST",
            vtUrl,
            headers,
            body=body,
            process_response=process_response,
            error_prefix="VT add to collection",
        )

    # Legacy methods for backward compatibility
    def postcomment(self, resource):
        """Send a comment to VirusTotal for a file"""
        return self._post_comment("files", resource, "Comment")

    def postcomment_url(self, url_id):
        """Send a comment to VirusTotal for a URL"""
        return self._post_comment("urls", url_id, "URL comment")


@implementer(IBodyProducer)
class StringProducer:
    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return defer.succeed(None)

    def pauseProducing(self):
        pass

    def resumeProducing(self):
        pass

    def stopProducing(self):
        pass


def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTPS instance
    """
    BOUNDARY = b"----------ThIs_Is_tHe_bouNdaRY_$"
    L = []
    for key, value in fields:
        L.append(b"--" + BOUNDARY)
        L.append(b'Content-Disposition: form-data; name="%s"' % key.encode())
        L.append(b"")
        L.append(value.encode())
    for key, filename, value in files:
        L.append(b"--" + BOUNDARY)
        L.append(
            b'Content-Disposition: form-data; name="%s"; filename="%s"'
            % (key.encode(), filename.encode())
        )
        L.append(b"Content-Type: application/octet-stream")
        L.append(b"")
        L.append(value.read())
    L.append(b"--" + BOUNDARY + b"--")
    L.append(b"")
    body = b"\r\n".join(L)
    content_type = b"multipart/form-data; boundary=%s" % BOUNDARY

    return content_type, body
