"""
Send downloaded/uplaoded files to Cuckoo
"""

from __future__ import absolute_import, division

import os

try:
    from urllib.parse import urlparse, urljoin
except ImportError:
    from urlparse import urlparse, urljoin

import requests
from requests.auth import HTTPBasicAuth

import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):

    def __init__(self):
        self.url_base = CONFIG.get('output_cuckoo', 'url_base').encode('utf-8')
        self.api_user = CONFIG.get('output_cuckoo', 'user')
        self.api_passwd = CONFIG.get('output_cuckoo', 'passwd', raw=True)
        self.cuckoo_force = int(CONFIG.getboolean('output_cuckoo', 'force'))
        cowrie.core.output.Output.__init__(self)

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
        res = None
        try:
            print("Looking for tasks for: {}".format(sha256))
            res = requests.get(
                urljoin(
                    self.url_base,
                    "/files/view/sha256/{}".format(sha256)
                ),
                verify=False,
                auth=HTTPBasicAuth(
                    self.api_user,
                    self.api_passwd
                ),
                timeout=60
            )
            if res and res.ok:
                print("Sample found in Sandbox, with ID: {}".format(res.json().get("sample", {}).get("id", 0)))
                res = True
        except Exception as e:
            print(e)

        return res

    def postfile(self, artifact, fileName):
        """
        Send a file to Cuckoo
        """
        files = {"file": (fileName, open(artifact, "rb").read())}
        try:
            res = requests.post(
                urljoin(
                    self.url_base,
                    "tasks/create/file"
                ).encode("utf-8"),
                files=files,
                auth=HTTPBasicAuth(
                    self.api_user,
                    self.api_passwd
                ),
                verify=False
            )
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
            res = requests.post(
                urljoin(
                    self.url_base,
                    "tasks/create/url"
                ).encode("utf-8"),
                data=data,
                auth=HTTPBasicAuth(
                    self.api_user,
                    self.api_passwd
                ),
                verify=False
            )
            if res and res.ok:
                print("Cuckoo Request: {}, Task created with ID: {}".format(res.status_code, res.json()["task_id"]))
            else:
                print("Cuckoo Request failed: {}".format(res.status_code))
        except Exception as e:
            print("Cuckoo Request failed: {}".format(e))
        return
