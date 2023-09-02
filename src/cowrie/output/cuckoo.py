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
Send downloaded/uplaoded files to Cuckoo
"""

from __future__ import annotations

import os
from urllib.parse import urljoin, urlparse

import requests
from requests.auth import HTTPBasicAuth

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


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

    def stop(self):
        """
        Stop output plugin
        """
        pass

    def write(self, entry):
        if entry["eventid"] == "cowrie.session.file_download":
            log.msg("Sending file to Cuckoo")
            p = urlparse(entry["url"]).path
            if p == "":
                fileName = entry["shasum"]
            else:
                b = os.path.basename(p)
                if b == "":
                    fileName = entry["shasum"]
                else:
                    fileName = b

            if (
                self.cuckoo_force
                or self.cuckoo_check_if_dup(os.path.basename(entry["outfile"])) is False
            ):
                self.postfile(entry["outfile"], fileName)

        elif entry["eventid"] == "cowrie.session.file_upload":
            if (
                self.cuckoo_force
                or self.cuckoo_check_if_dup(os.path.basename(entry["outfile"])) is False
            ):
                log.msg("Sending file to Cuckoo")
                self.postfile(entry["outfile"], entry["filename"])

    def cuckoo_check_if_dup(self, sha256: str) -> bool:
        """
        Check if file already was analyzed by cuckoo
        """
        try:
            log.msg(f"Looking for tasks for: {sha256}")
            res = requests.get(
                urljoin(self.url_base, f"/files/view/sha256/{sha256}".encode()),
                verify=False,
                auth=HTTPBasicAuth(self.api_user, self.api_passwd),
                timeout=60,
            )
            if res and res.ok:
                log.msg(
                    "Sample found in Sandbox, with ID: {}".format(
                        res.json().get("sample", {}).get("id", 0)
                    )
                )
                return True
        except Exception as e:
            log.msg(e)

        return False

    def postfile(self, artifact, fileName):
        """
        Send a file to Cuckoo
        """
        with open(artifact, "rb") as art:
            files = {"file": (fileName, art.read())}
        try:
            res = requests.post(
                urljoin(self.url_base, b"tasks/create/file"),
                files=files,
                auth=HTTPBasicAuth(self.api_user, self.api_passwd),
                verify=False,
            )
            if res and res.ok:
                log.msg(
                    "Cuckoo Request: {}, Task created with ID: {}".format(
                        res.status_code, res.json()["task_id"]
                    )
                )
            else:
                log.msg(f"Cuckoo Request failed: {res.status_code}")
        except Exception as e:
            log.msg(f"Cuckoo Request failed: {e}")

    def posturl(self, scanUrl):
        """
        Send a URL to Cuckoo
        """
        data = {"url": scanUrl}
        try:
            res = requests.post(
                urljoin(self.url_base, b"tasks/create/url"),
                data=data,
                auth=HTTPBasicAuth(self.api_user, self.api_passwd),
                verify=False,
            )
            if res and res.ok:
                log.msg(
                    "Cuckoo Request: {}, Task created with ID: {}".format(
                        res.status_code, res.json()["task_id"]
                    )
                )
            else:
                log.msg(f"Cuckoo Request failed: {res.status_code}")
        except Exception as e:
            log.msg(f"Cuckoo Request failed: {e}")
