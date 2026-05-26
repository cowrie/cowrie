# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Send files to https://malshare.com/
More info https://malshare.com/doc.php
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

import treq
from twisted.internet import defer, error
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

HTTP_TIMEOUT = 20


class Output(cowrie.core.output.Output):
    """
    malshare output
    """

    apiKey: str

    def start(self):
        """
        Start output plugin
        """
        self.apiKey = CowrieConfig.get("output_malshare", "api_key")

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

            self.postfile(event["outfile"], fileName)

        elif event["eventid"] == "cowrie.session.file_upload":
            self.postfile(event["outfile"], event["filename"])

    @defer.inlineCallbacks
    def postfile(self, artifact, fileName):
        """
        Send a file to MalShare
        """
        url = (
            f"https://malshare.com/api.php?api_key={self.apiKey}&action=upload"
        ).encode()
        try:
            with open(artifact, "rb") as upload:
                response = yield treq.post(
                    url=url,
                    files={"upload": (fileName, upload)},
                    timeout=HTTP_TIMEOUT,
                    allow_redirects=False,
                )
        except (
            defer.CancelledError,
            error.ConnectingCancelledError,
            error.DNSLookupError,
        ) as e:
            log.msg(f"MalShare Request failed: {e}")
            return
        except Exception as e:
            log.msg(f"MalShare Request failed: {e}")
            return

        # Drain the body so the connection returns to the pool.
        yield response.text()

        if 200 <= response.code < 300:
            log.msg("Submitted to MalShare")
        else:
            log.msg(f"MalShare Request failed: {response.code}")
