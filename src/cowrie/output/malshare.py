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
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS`` AND ANY EXPRESS OR
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
Send files to https://malshare.com/
More info https://malshare.com/doc.php
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

import requests

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    malshare output

    TODO: use `treq`
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

    def write(self, entry):
        if entry["eventid"] == "cowrie.session.file_download":
            p = urlparse(entry["url"]).path
            if p == "":
                fileName = entry["shasum"]
            else:
                b = os.path.basename(p)
                if b == "":
                    fileName = entry["shasum"]
                else:
                    fileName = b

            self.postfile(entry["outfile"], fileName)

        elif entry["eventid"] == "cowrie.session.file_upload":
            self.postfile(entry["outfile"], entry["filename"])

    def postfile(self, artifact, fileName):
        """
        Send a file to MalShare
        """
        try:
            res = requests.post(
                "https://malshare.com/api.php?api_key="
                + self.apiKey
                + "&action=upload",
                files={"upload": open(artifact, "rb")},
            )
            if res and res.ok:
                log.msg("Submitted to MalShare")
            else:
                log.msg(f"MalShare Request failed: {res.status_code}")
        except Exception as e:
            log.msg(f"MalShare Request failed: {e}")
