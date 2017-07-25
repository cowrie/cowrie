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

from __future__ import division, absolute_import

import json
import os
try:
    from urllib.parse import urlparse, urljoin
except ImportError:
    from urlparse import urlparse, urljoin

import requests
from requests.auth import HTTPBasicAuth

import cowrie.core.output


class Output(cowrie.core.output.Output):
    """
    """

    def __init__(self, cfg):
        self.url_base = cfg.get("output_cuckoo", "url_base").encode("utf-8")
        self.api_user = cfg.get("output_cuckoo", "user")
        self.api_passwd = cfg.get("output_cuckoo", "passwd")
        self.cuckoo_force = int(cfg.get("output_cuckoo", "force"))
        cowrie.core.output.Output.__init__(self, cfg)


    def start(self):
        """
        Start output plugin
        """
        pass


    def stop(self):
        """
        Stop output plugin
        """
        pass


    def write(self, entry):
        """
        """
        if entry["eventid"] == "cowrie.session.file_download":
            print("Sending file to Cuckoo")
            p = urlparse(entry["url"]).path
            if p == "":
                fileName = entry["shasum"]
            else:
                b = os.path.basename(p)
                if b == "":
                    fileName = entry["shasum"]
                else:
                    fileName = b

            if self.cuckoo_force or self.cuckoo_check_if_dup(os.path.basename(entry["outfile"])) is False:
                self.postfile(entry["outfile"], fileName)

        elif entry["eventid"] == "cowrie.session.file_upload":
            if self.cuckoo_force or self.cuckoo_check_if_dup(os.path.basename(entry["outfile"])) is False:
                print("Sending file to Cuckoo")
                self.postfile(entry["outfile"], entry["filename"])


    def cuckoo_check_if_dup(self, sha256):
        """
        Check if file already was analyzed by cuckoo
        """
        res = ""
        try:
            print("Looking for tasks for: {}".format(sha256))
            res = requests.get(urljoin(self.url_base, "/files/view/sha256/{}".format(sha256)),
                verify=False,
                auth=HTTPBasicAuth(self.api_user,self.api_passwd),
                timeout=60)
            if res and res.ok:
                print("Sample found in Sandbox, with ID: {}".format(res.json().get("sample", {}).get("id", 0)))
        except Exception as e:
            print(e)

        return res

    def postfile(self, artifact, fileName):
        """
        Send a file to Cuckoo
        """
        files = {"file": (fileName, open(artifact, "rb").read())}
        try:
            res = requests.post(urljoin(self.url_base, "tasks/create/file").encode("utf-8"), files=files, auth=HTTPBasicAuth(
                            self.api_user,
                            self.api_passwd
                        ),
                        verify=False)
            if res and res.ok:
                print("Cuckoo Request: {}, Task created with ID: {}".format(res.status_code, res.json()["task_id"]))
            else:
                print("Cuckoo Request failed: {}".format(res.status_code))
        except Exception as e:
            print("Cuckoo Request failed: {}".format(e))
        return


    def posturl(self, scanUrl):
        """
        Send a URL to Cuckoo
        """
        data = {"url": scanUrl}
        try:
            res = requests.post(urljoin(self.url_base, "tasks/create/url").encode("utf-8"), data=data, auth=HTTPBasicAuth(
                            self.api_user,
                            self.api_passwd
                        ),
                        verify=False)
            if res and res.ok:
                print("Cuckoo Request: {}, Task created with ID: {}".format(res.status_code, res.json()["task_id"]))
            else:
                print("Cuckoo Request failed: {}".format(res.status_code))
        except Exception as e:
            print("Cuckoo Request failed: {}".format(e))
        return
