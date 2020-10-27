# Copyright (c) 2020 Julius ter Pelkwijk <pelkwijk@gmail.com>
# Based on code made by Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import absolute_import, division

import os
import zipfile

from twisted.python import log

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import A_REALFILE

commands = {}


class command_unzip(HoneyPotCommand):

    def mkfullpath(self, path, f):
        l, d = path.split('/'), []
        while len(l):
            d.append(l.pop(0))
            dir = '/' + '/'.join(d)
            if not self.fs.exists(dir):
                self.fs.mkdir(dir, 0, 0, 4096, 33188)

    def call(self):
        if len(self.args) == 0 or self.args[0].startswith('-'):
            self.write(
            """UnZip 6.00 of 20 April 2009, by Debian. Original by Info-ZIP.

Usage: unzip [-Z] [-opts[modifiers]] file[.zip] [list] [-x xlist] [-d exdir]
  Default action is to extract files in list, except those in xlist, to exdir;
  file[.zip] may be a wildcard.  -Z => ZipInfo mode ("unzip -Z" for usage).

  -p  extract files to pipe, no messages     -l  list files (short format)
  -f  freshen existing files, create none    -t  test compressed archive data
  -u  update files, create if necessary      -z  display archive comment only
  -v  list verbosely/show version info       -T  timestamp archive to latest
  -x  exclude files that follow (in xlist)   -d  extract files into exdir
modifiers:
  -n  never overwrite existing files         -q  quiet mode (-qq => quieter)
  -o  overwrite files WITHOUT prompting      -a  auto-convert any text files
  -j  junk paths (do not make directories)   -aa treat ALL files as text
  -U  use escapes for all non-ASCII Unicode  -UU ignore any Unicode fields
  -C  match filenames case-insensitively     -L  make (some) names lowercase
  -X  restore UID/GID info                   -V  retain VMS version numbers
  -K  keep setuid/setgid/tacky permissions   -M  pipe through "more" pager
See "unzip -hh" or unzip.txt for more help.  Examples:
  unzip data1 -x joe   => extract all files except joe from zipfile data1.zip
  unzip -p foo | more  => send contents of foo.zip via pipe into program more
  unzip -fo foo ReadMe => quietly replace existing ReadMe if archive file newer
"""
            )
            return

        filename = self.args[0]

        path = self.fs.resolve_path(filename, self.protocol.cwd)
        if not path:
            self.write('unzip:  cannot find or open {0}, {0}.zip or {0}.ZIP.\n'.format(filename))
            return
        if not self.protocol.fs.exists(path):
            if not self.protocol.fs.exists(path + ".zip"):
                self.write('unzip:  cannot find or open {0}, {0}.zip or {0}.ZIP.\n'.format(filename))
                return
            else:
                path = path + ".zip"

        f = self.fs.getfile(path)
        if not f[A_REALFILE]:
            self.write(""" End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.  In the
  latter case the central directory and zipfile comment will be found on
  the last disk(s) of this archive.
"""
            )
            self.write('unzip:  cannot find or open {0}, {0}.zip or {0}.ZIP.\n'.format(filename))
            return

        try:
            t = zipfile.ZipFile(f[A_REALFILE]).infolist()
        except Exception:
            self.write(""" End-of-central-directory signature not found.  Either this file is not
  a zipfile, or it constitutes one disk of a multi-part archive.  In the
  latter case the central directory and zipfile comment will be found on
  the last disk(s) of this archive.
"""
            )
            self.write('unzip:  cannot find or open {0}, {0}.zip or {0}.ZIP.\n'.format(filename))
            return
        self.write('Archive:  {}\n'.format(filename))
        for f in t:
            dest = self.fs.resolve_path(f.filename.strip('/'), self.protocol.cwd)
            self.write('  inflating: {0}\n'.format(f.filename))
            if not len(dest):
                continue
            if f.is_dir():
                self.fs.mkdir(dest, 0, 0, 4096, 33188)
            elif not f.is_dir():
                self.mkfullpath(os.path.dirname(dest), f)
                self.fs.mkfile(dest, 0, 0, f.file_size, 33188)
            else:
                log.msg("  skipping: {}\n".format(f.name))


commands['/bin/unzip'] = command_unzip
commands['unzip'] = command_unzip
