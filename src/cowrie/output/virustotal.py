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
from typing import Any
from urllib.parse import urlencode, urlparse

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet import reactor
from twisted.python import log
from twisted.web import client, http_headers
from twisted.web.iweb import IBodyProducer

import cowrie.core.output
from cowrie.core.config import CowrieConfig

COWRIE_USER_AGENT = "Cowrie Honeypot"
VTAPI_URL = "https://www.virustotal.com/api/v3/"
COMMENT = "First seen by #Cowrie SSH/telnet Honeypot http://github.com/cowrie/cowrie"
TIME_SINCE_FIRST_DOWNLOAD = datetime.timedelta(minutes=1)


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
            "output_virustotal", "scan_url", fallback=False
        )
        self.commenttext = CowrieConfig.get(
            "output_virustotal", "commenttext", fallback=COMMENT
        )
        self.agent = client.Agent(reactor)

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

    def scanfile(self, event):
        """
        Check file scan report for a hash
        Argument is full event so we can access full file later on
        """
        vtUrl = f"{VTAPI_URL}files/{event['shasum']}".encode()
        headers = http_headers.Headers(
            {"User-Agent": [COWRIE_USER_AGENT], "x-apikey": [self.apiKey]}
        )
        d = self.agent.request(b"GET", vtUrl, headers)

        def cbResponse(response):
            """
            Main response callback, check HTTP response code
            """
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                return d
            else:
                log.msg(f"VT scanfile failed: {response.code} {response.phrase}")

        def cbBody(body):
            """
            Received body
            """
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)

        def cbError(failure):
            log.msg("VT: Error in scanfile")
            failure.printTraceback()

        def processResult(result):
            """
            Extract the information we need from the body
            """
            if self.debug:
                log.msg(f"VT scanfile result: {result}")
            result = result.decode("utf8")
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
                        if b == "":
                            fileName = event["shasum"]
                        else:
                            fileName = b
                    except KeyError:
                        fileName = event["shasum"]

                    if self.upload is True:
                        return self.postfile(event["outfile"], fileName)
                    else:
                        return
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
                # Add detailed report to json log
                scans_summary: dict[str, dict[str, str]] = {}
                for engine, result in last_analysis_results.items():
                    engine_key = engine.lower()
                    scans_summary[engine_key] = {}
                    scans_summary[engine_key]["detected"] = str(
                        result.get("category") in ["malicious", "suspicious"]
                    ).lower()
                    scans_summary[engine_key]["result"] = str(
                        result.get("result", "")
                    ).lower()

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
                # v3 API doesn't have a direct permalink, construct one
                log.msg(
                    "VT: permalink: https://www.virustotal.com/gui/file/{}".format(
                        event["shasum"]
                    )
                )
            else:
                log.msg("VT: unexpected response format")

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d

    def postfile(self, artifact, fileName):
        """
        Send a file to VirusTotal
        """
        vtUrl = f"{VTAPI_URL}files".encode()
        fields = {}  # v3 API doesn't need apikey in form data
        files = {("file", fileName, open(artifact, "rb"))}
        if self.debug:
            log.msg(f"submitting to VT: {files!r}")
        contentType, body = encode_multipart_formdata(fields, files)
        producer = StringProducer(body)
        headers = http_headers.Headers(
            {
                "User-Agent": [COWRIE_USER_AGENT],
                "Accept": ["*/*"],
                "Content-Type": [contentType],
                "x-apikey": [self.apiKey],
            }
        )

        d = self.agent.request(b"POST", vtUrl, headers, producer)

        def cbBody(body):
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)

        def cbResponse(response):
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d
            else:
                log.msg(f"VT postfile failed: {response.code} {response.phrase}")

        def cbError(failure):
            failure.printTraceback()

        def processResult(result):
            if self.debug:
                log.msg(f"VT postfile result: {result}")
            result = result.decode("utf8")
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
                    # Post comment if enabled
                    if self.comment is True:
                        return self.postcomment(file_id)
                    else:
                        return
                else:
                    log.msg("VT: Upload successful but no file ID returned")
            else:
                log.msg("VT: unexpected upload response format")

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d

    def scanurl(self, event):
        """
        Check url scan report for a hash
        """
        if event["url"] in self.url_cache:
            log.msg(
                "output_virustotal: url {} was already successfully submitted".format(
                    event["url"]
                )
            )
            return

        # First submit the URL for scanning, then get the report
        # v3 API requires URL to be base64 encoded with padding removed
        url_id = base64.urlsafe_b64encode(event["url"].encode()).decode().rstrip("=")

        vtUrl = f"{VTAPI_URL}urls/{url_id}".encode()
        headers = http_headers.Headers(
            {"User-Agent": [COWRIE_USER_AGENT], "x-apikey": [self.apiKey]}
        )
        d = self.agent.request(b"GET", vtUrl, headers)

        def cbResponse(response):
            """
            Main response callback, checks HTTP response code
            """
            if response.code == 200:
                log.msg(f"VT scanurl successful: {response.code} {response.phrase}")
                d = client.readBody(response)
                d.addCallback(cbBody)
                return d
            else:
                log.msg(f"VT scanurl failed: {response.code} {response.phrase}")

        def cbBody(body):
            """
            Received body
            """
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)

        def cbError(failure):
            log.msg("cbError")
            failure.printTraceback()

        def processResult(result):
            """
            Extract the information we need from the body
            """
            if self.debug:
                log.msg(f"VT scanurl result: {result}")
            if result == b"[]\n":
                log.err(f"VT scanurl did not return results: {result}")
                return
            result = result.decode("utf8")
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
                # Add detailed report to json log
                scans_summary: dict[str, dict[str, str]] = {}
                for engine, result in last_analysis_results.items():
                    engine_key = engine.lower()
                    scans_summary[engine_key] = {}
                    scans_summary[engine_key]["detected"] = str(
                        result.get("category") in ["malicious", "suspicious"]
                    ).lower()
                    scans_summary[engine_key]["result"] = str(
                        result.get("result", "")
                    ).lower()

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
                # v3 API doesn't have a direct permalink, construct one
                log.msg(
                    "VT: permalink: https://www.virustotal.com/gui/url/{}".format(
                        url_id
                    )
                )
            else:
                log.msg("VT: unexpected response format")

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d

    def submiturl(self, event):
        """
        Submit a URL for scanning in VirusTotal v3 API
        """
        vtUrl = f"{VTAPI_URL}urls".encode()
        headers = http_headers.Headers(
            {
                "User-Agent": [COWRIE_USER_AGENT],
                "x-apikey": [self.apiKey],
                "Content-Type": ["application/x-www-form-urlencoded"],
            }
        )
        body = StringProducer(urlencode({"url": event["url"]}).encode("utf-8"))
        d = self.agent.request(b"POST", vtUrl, headers, body)

        def cbResponse(response):
            if response.code == 200:
                log.msg("VT: URL submitted successfully for scanning")
                return
            else:
                log.msg(f"VT: URL submission failed: {response.code} {response.phrase}")

        def cbError(failure):
            log.msg("VT: Error submitting URL")
            failure.printTraceback()

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d

    def postcomment(self, resource):
        """
        Send a comment to VirusTotal with Twisted
        """
        vtUrl = f"{VTAPI_URL}files/{resource}/comments".encode()
        comment_data = {
            "data": {"type": "comment", "attributes": {"text": self.commenttext}}
        }
        headers = http_headers.Headers(
            {
                "User-Agent": [COWRIE_USER_AGENT],
                "x-apikey": [self.apiKey],
                "Content-Type": ["application/json"],
            }
        )
        body = StringProducer(json.dumps(comment_data).encode("utf-8"))
        d = self.agent.request(b"POST", vtUrl, headers, body)

        def cbBody(body):
            return processResult(body)

        def cbPartial(failure):
            """
            Google HTTP Server does not set Content-Length. Twisted marks it as partial
            """
            return processResult(failure.value.response)

        def cbResponse(response):
            if response.code == 200:
                d = client.readBody(response)
                d.addCallback(cbBody)
                d.addErrback(cbPartial)
                return d
            else:
                log.msg(f"VT postcomment failed: {response.code} {response.phrase}")

        def cbError(failure):
            failure.printTraceback()

        def processResult(result):
            if self.debug:
                log.msg(f"VT postcomment result: {result}")
            result = result.decode("utf8")
            j = json.loads(result)

            # Check for errors in v3 API response
            if "error" in j:
                log.msg(
                    f"VT: Comment error - {j['error']['code']}: {j['error']['message']}"
                )
                return False

            # Process successful comment response
            if "data" in j:
                log.msg("VT: Comment posted successfully")
                return True
            else:
                log.msg("VT: unexpected comment response format")
                return False

        d.addCallback(cbResponse)
        d.addErrback(cbError)
        return d


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
