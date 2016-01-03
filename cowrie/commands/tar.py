# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import random
import tarfile
import os

from twisted.python import log

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *

commands = {}


class command_tar(HoneyPotCommand):
    """
    """

    def mkfullpath(self, path, f):
        """
        """
        l, d = path.split('/'), []
        while len(l):
            d.append(l.pop(0))
            if not self.fs.exists('/'.join(d)):
                self.fs.mkdir('/'.join(d), 0, 0, 4096, f.mode, f.mtime)


    def call(self):
        """
        """
        if len(self.args) < 2:
            self.write('tar: You must specify one of the `-Acdtrux\' options\n')
            self.write('Try `tar --help\' or `tar --usage\' for more information.\n')
            return

        filename = self.args[1]

        extract = False
        if 'x' in self.args[0]:
            extract = True
        verbose = False
        if 'v' in self.args[0]:
            verbose = True

        path = self.fs.resolve_path(filename, self.protocol.cwd)
        if not path or not self.protocol.fs.exists(path):
            self.write('tar: %s: Cannot open: No such file or directory\n' % \
                filename)
            self.write('tar: Error is not recoverable: exiting now\n')
            self.write('tar: Child returned status 2\n')
            self.write('tar: Error exit delayed from previous errors\n')
            return

        f = self.fs.getfile(path)
        if not f[A_REALFILE]:
            self.write('tar: this does not look like a tar archive\n')
            self.write('tar: skipping to next header\n')
            self.write('tar: error exit delayed from previous errors\n')
            return

        try:
            t = tarfile.open(f[A_REALFILE])
        except:
            self.write('tar: this does not look like a tar archive\n')
            self.write('tar: skipping to next header\n')
            self.write('tar: error exit delayed from previous errors\n')
            return

        for f in t:
            dest = self.fs.resolve_path(f.name.strip('/'), self.protocol.cwd)
            if verbose:
                self.write(f.name+'\n')
            if not extract or not len(dest):
                continue
            if f.isdir():
                self.fs.mkdir(dest, 0, 0, 4096, f.mode, f.mtime)
            elif f.isfile():
                self.mkfullpath(os.path.dirname(dest), f)
                self.fs.mkfile(dest, 0, 0, f.size, f.mode, f.mtime)
            else:
                log.msg( 'tar: skipping [%s]' % f.name )

commands['/bin/tar'] = command_tar

# vim: set sw=4 et:
