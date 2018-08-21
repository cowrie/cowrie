"""
Send files to https://malshare.com/
More info https://malshare.com/doc.php
"""

from __future__ import absolute_import, division

import os

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
import requests

import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):

    def __init__(self):
        self.enabled = CONFIG.getboolean('output_malshare', 'enabled')
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
            print("Sending file to MalShare")
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
            print("Sending file to MalShare")
            self.postfile(entry["outfile"], entry["filename"])

    def postfile(self, artifact, fileName):
        """
        Send a file to MalShare
        """
        if self.enabled:
            try:
                res = requests.post(
                    "https://malshare.com/api.php?mode=cli",
                    files={fileName: open(artifact, "rb")},
                    verify=False
                )
                if res and res.ok:
                    print("Submited to MalShare")
                else:
                    print("MalShare Request failed: {}".format(res.status_code))
            except Exception as e:
                print("MalShare Request failed: {}".format(e))
        return
