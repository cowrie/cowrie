# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from core.honeypot import HoneyPotCommand
from core.fs import *
from commands import dice
import time, random, tarfile, os

commands = {}

class command_tar(HoneyPotCommand):
    def call(self):
        if len(self.args) < 2:
            self.writeln('tar: You must specify one of the `-Acdtrux\' options')
            self.writeln('Try `tar --help\' or `tar --usage\' for more information.')
            return

        filename = self.args[1]

        extract = False
        if 'x' in self.args[0]:
            extract = True
        verbose = False
        if 'v' in self.args[0]:
            verbose = True

        path = self.fs.resolve_path(filename, self.honeypot.cwd)
        if not path or not self.honeypot.fs.exists(path):
            self.writeln('tar: %s: Cannot open: No such file or directory' % \
                filename)
            self.writeln('tar: Error is not recoverable: exiting now')
            self.writeln('tar: Child returned status 2')
            self.writeln('tar: Error exit delayed from previous errors')
            return

        f = self.fs.getfile(path)
        if not f[A_REALFILE]:
            self.writeln('tar: this does not look like a tar archive')
            self.writeln('tar: skipping to next header')
            self.writeln('tar: error exit delayed from previous errors')
            return

        try:
            t = tarfile.open(f[A_REALFILE])
        except:
            self.writeln('tar: this does not look like a tar archive')
            self.writeln('tar: skipping to next header')
            self.writeln('tar: error exit delayed from previous errors')
            return

        for f in t:
            dest = self.fs.resolve_path(f.name.strip('/'), self.honeypot.cwd)
            if verbose:
                self.writeln(f.name)
            if not extract or not len(dest):
                continue
            if f.isdir():
                self.fs.mkdir(dest, 0, 0, 4096, f.mode, f.mtime)
            elif f.isfile():
                self.fs.mkfile(dest, 0, 0, f.size, f.mode, f.mtime)
                self.honeypot.commands[dest] = random.choice(dice.clist)
            else:
                print 'tar: skipping [%s]' % f.name
commands['/bin/tar'] = command_tar

# vim: set sw=4 et:
