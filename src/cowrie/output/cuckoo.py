# SPDX-FileCopyrightText: 2017 doomedraven
# SPDX-FileCopyrightText: 2017-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Send downloaded/uplaoded files to Cuckoo
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

from treq.client import HTTPClient
from twisted.internet import defer, error, reactor, ssl
from twisted.python import log
from twisted.web import client
from twisted.web.iweb import IPolicyForHTTPS
from zope.interface import implementer

import cowrie.core.output
from cowrie.core.config import CowrieConfig

if TYPE_CHECKING:
    from collections.abc import Generator

HTTP_TIMEOUT = 20


@implementer(IPolicyForHTTPS)
class _NoVerifyContextFactory:
    """
    Cuckoo deployments are typically local with self-signed certs,
    so verification is skipped on purpose (matches the old verify=False
    behaviour of requests).
    """

    def creatorForNetloc(self, hostname, port):
        return ssl.CertificateOptions(verify=False)


class Output(cowrie.core.output.Output):
    """
    cuckoo output
    """

    api_user: str
    api_passwd: str
    url_base: bytes
    cuckoo_force: int

    def start(self):
        """
        Start output plugin
        """
        self.url_base = CowrieConfig.get("output_cuckoo", "url_base").encode("utf-8")
        self.api_user = CowrieConfig.get("output_cuckoo", "user")
        self.api_passwd = CowrieConfig.get("output_cuckoo", "passwd", raw=True)
        self.cuckoo_force = int(CowrieConfig.getboolean("output_cuckoo", "force"))
        self.client = HTTPClient(client.Agent(reactor, _NoVerifyContextFactory()))

    def stop(self):
        """
        Stop output plugin
        """
        pass

    def write(self, event):
        if event["eventid"] == "cowrie.session.file_download":
            p = urlparse(event["url"]).path
            if p == "":
                fileName = event["shasum"]
            else:
                b = os.path.basename(p)
                if b == "":
                    fileName = event["shasum"]
                else:
                    fileName = b

            self._maybe_postfile(event["outfile"], fileName)

        elif event["eventid"] == "cowrie.session.file_upload":
            self._maybe_postfile(event["outfile"], event["filename"])

    @defer.inlineCallbacks
    def _maybe_postfile(self, outfile, fileName):
        if not self.cuckoo_force:
            is_dup = yield self.cuckoo_check_if_dup(os.path.basename(outfile))
            if is_dup:
                return
        log.msg("Sending file to Cuckoo")
        yield self.postfile(outfile, fileName)

    @defer.inlineCallbacks
    def cuckoo_check_if_dup(self, sha256: str) -> Generator[Any, Any, bool]:
        """
        Check if file already was analyzed by cuckoo
        """
        try:
            log.msg(f"Looking for tasks for: {sha256}")
            response = yield self.client.get(
                urljoin(self.url_base, f"/files/view/sha256/{sha256}".encode()),
                auth=(self.api_user, self.api_passwd),
                timeout=HTTP_TIMEOUT,
            )
        except (
            defer.CancelledError,
            error.ConnectingCancelledError,
            error.DNSLookupError,
        ) as e:
            log.msg(e)
            return False
        except Exception as e:
            log.msg(e)
            return False

        if 200 <= response.code < 300:
            body = yield response.json()
            log.msg(
                "Sample found in Sandbox, with ID: {}".format(
                    body.get("sample", {}).get("id", 0)
                )
            )
            return True

        # Drain the body so the connection returns to the pool.
        yield response.text()
        return False

    @defer.inlineCallbacks
    def postfile(self, artifact, fileName):
        """
        Send a file to Cuckoo
        """
        try:
            with open(artifact, "rb") as art:
                response = yield self.client.post(
                    urljoin(self.url_base, b"tasks/create/file"),
                    files={"file": (fileName, art)},
                    auth=(self.api_user, self.api_passwd),
                    timeout=HTTP_TIMEOUT,
                )
        except Exception as e:
            log.msg(f"Cuckoo Request failed: {e}")
            return

        if 200 <= response.code < 300:
            body = yield response.json()
            log.msg(
                "Cuckoo Request: {}, Task created with ID: {}".format(
                    response.code, body["task_id"]
                )
            )
        else:
            yield response.text()
            log.msg(f"Cuckoo Request failed: {response.code}")

    @defer.inlineCallbacks
    def posturl(self, scanUrl):
        """
        Send a URL to Cuckoo
        """
        try:
            response = yield self.client.post(
                urljoin(self.url_base, b"tasks/create/url"),
                data={"url": scanUrl},
                auth=(self.api_user, self.api_passwd),
                timeout=HTTP_TIMEOUT,
            )
        except Exception as e:
            log.msg(f"Cuckoo Request failed: {e}")
            return

        if 200 <= response.code < 300:
            body = yield response.json()
            log.msg(
                "Cuckoo Request: {}, Task created with ID: {}".format(
                    response.code, body["task_id"]
                )
            )
        else:
            yield response.text()
            log.msg(f"Cuckoo Request failed: {response.code}")
