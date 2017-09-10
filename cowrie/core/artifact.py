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

class Artifact:
    """
    """
    sizeLimit = 0
    size = 0
    tooBig = False

    def __init__(self, cfg, label):
        """
        """
        self.label = label
        self.artifactDir = cfg.get('honeypot', 'download_path')
        try:
            self.sizeLimit = int(cfg.get('honeypot', 'download_limit_size'))
        except:
            self.sizeLimit = 0

        self.fp = tempfile.NamedTemporaryFile(dir=self.artifactDir, delete=False)
        self.tempFilename = self.fp.name
        log.msg( "temp opened at {}".format(self.tempFilename))


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
        self.size += len(bytes)
        if self.tooBig:
            return
        if self.size > self.sizeLimit:
            self.tooBig = True
            return

        return self.fp.write(bytes)


    def fileno(self):
        """
        """
        return self.fp.fileno()


    def close(self):
        """
        """
        return


    def finish(self, keepEmpty=True):
        """
        """
        self.fp.seek(0)
        shasum = hashlib.sha256(self.fp.read()).hexdigest()
        self.fp.close()
        shasumFilename = self.artifactDir + "/" + shasum
   
        log.msg( "artifacthash {}".format(shasumFilename))

        if self.size == 0 and keepEmpty == False:
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

        log.msg( "temp closed at {}".format(shasum))

        return shasum, shasumFilename, self.size


