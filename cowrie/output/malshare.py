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

from __future__ import division, absolute_import

import os
try:
    from urllib.parse import urlparse, urljoin
except ImportError:
    from urlparse import urlparse, urljoin

import requests
import cowrie.core.output
from cowrie.core.config import CONFIG

class Output(cowrie.core.output.Output):
    """
    """

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
        """
        """
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
                res = requests.post("https://malshare.com/api.php?mode=cli",
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
