# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>

"""
This module contains code to handling saving of honeypot artifacts
These will typically be files uploaded to the honeypot and files
downloaded inside the honeypot, or input being piped in.

Code behaves like a normal Python file handle.

Example:

    with Artifact(name) as f:
        f.write("abc")

or:

    g = Artifact("testme2")
    g.write( "def" )
    g.close()

"""

from __future__ import division, absolute_import

import hashlib
import os
import re
import time
import tempfile

from twisted.python import log

from cowrie.core.config import CONFIG

class Artifact:
    """
    """

    def __init__(self, label):
        """
        """
        self.label = label
        self.artifactDir = CONFIG.get('honeypot', 'download_path')

        self.fp = tempfile.NamedTemporaryFile(dir=self.artifactDir, delete=False)
        self.tempFilename = self.fp.name


    def __enter__(self):
        """
        """
        return self.fp


    def __exit__(self, exception_type, exception_value, trace):
        """
        """
        self.close()


    def write(self, bytes):
        """
        """
        self.fp.write(bytes)


    def fileno(self):
        """
        """
        return self.fp.fileno()


    def close(self, keepEmpty=True):
        """
        """
        size = self.fp.tell()
        self.fp.seek(0)
        shasum = hashlib.sha256(self.fp.read()).hexdigest()
        self.fp.close()
        shasumFilename = self.artifactDir + "/" + shasum

        if size == 0 and keepEmpty == False:
            os.remove(self.fp.name)
        elif os.path.exists(shasumFilename):
            os.remove(self.fp.name)
        else:
            os.rename(self.fp.name, shasumFilename)

        # if size>0:
        #    linkName = self.artifactDir + "/" \
        #        + time.strftime('%Y%m%dT%H%M%S') \
        #        + "_" + re.sub('[^-A-Za-z0-9]', '_', self.label)
        #    os.symlink(shasum, linkName)

        return shasum, shasumFilename


