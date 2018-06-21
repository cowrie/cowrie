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
    g.write("def")
    g.close()

"""

from __future__ import division, absolute_import

import hashlib
import os
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
        self.closed = False

        self.shasum = ''
        self.shasumFilename = ''

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


    def close(self, keepEmpty=False):
        """
        """
        size = self.fp.tell()
        self.fp.seek(0)
        data = self.fp.read()
        self.fp.close()
        self.closed = True
        self.shasum = hashlib.sha256(data).hexdigest()
        self.shasumFilename = os.path.join(self.artifactDir, self.shasum)

        if size == 0 and not keepEmpty:
            log.msg("Not storing empty file")
            os.remove(self.fp.name)
        elif os.path.exists(self.shasumFilename):
            log.msg("Not storing duplicate content " + self.shasum)
            os.remove(self.fp.name)
        else:
            os.rename(self.fp.name, self.shasumFilename)
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(self.shasumFilename, 0o666 & ~umask)

        return self.shasum, self.shasumFilename


