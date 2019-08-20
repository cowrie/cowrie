# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains code to run a command
"""

from __future__ import absolute_import, division

import os
import re
import stat
import sys
import time

from twisted.internet import error
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig
from cowrie.shell import fs

# From Python3.6 we get the new shlex version
if sys.version_info.major >= 3 and sys.version_info.minor >= 6:
    import shlex
else:
    from cowrie.shell import shlex


class HoneyPotCommand(object):
    """
    This is the super class for all commands in cowrie/commands
    """

    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = list(args)
        self.environ = self.protocol.cmdstack[0].environ
        self.fs = self.protocol.fs
        self.data = None  # output data
        self.input_data = None  # used to store STDIN data passed via PIPE
        self.writefn = self.protocol.pp.outReceived
        self.errorWritefn = self.protocol.pp.errReceived
        # MS-DOS style redirect handling, inside the command
        # TODO: handle >>, 2>, etc
        if '>' in self.args or '>>' in self.args:
            if self.args[-1] in ['>', ">>"]:
                self.errorWrite("-bash: parse error near '\\n' \n")
                return
            self.writtenBytes = 0
            self.writefn = self.write_to_file
            if '>>' in self.args:
                index = self.args.index('>>')
                b_append = True
            else:
                index = self.args.index('>')
                b_append = False
            self.outfile = self.fs.resolve_path(str(self.args[(index + 1)]), self.protocol.cwd)
            del self.args[index:]
            p = self.fs.getfile(self.outfile)
            if not p or not p[fs.A_REALFILE] or p[fs.A_REALFILE].startswith('honeyfs') or not b_append:
                tmp_fname = '%s-%s-%s-redir_%s' % \
                            (time.strftime('%Y%m%d-%H%M%S'),
                             self.protocol.getProtoTransport().transportId,
                             self.protocol.terminal.transport.session.id,
                             re.sub('[^A-Za-z0-9]', '_', self.outfile))
                self.safeoutfile = os.path.join(CowrieConfig().get('honeypot', 'download_path'), tmp_fname)
                perm = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
                try:
                    self.fs.mkfile(self.outfile, 0, 0, 0, stat.S_IFREG | perm)
                except fs.FileNotFound:
                    # The outfile locates at a non-existing directory.
                    self.errorWrite('-bash: %s: No such file or directory\n' % self.outfile)
                    self.writefn = self.write_to_failed
                    self.outfile = None
                    self.safeoutfile = None
                except fs.PermissionDenied:
                    # The outfile locates in a file-system that doesn't allow file creation
                    self.errorWrite('-bash: %s: Permission denied\n' % self.outfile)
                    self.writefn = self.write_to_failed
                    self.outfile = None
                    self.safeoutfile = None

                else:
                    with open(self.safeoutfile, 'ab'):
                        self.fs.update_realfile(self.fs.getfile(self.outfile), self.safeoutfile)
            else:
                self.safeoutfile = p[fs.A_REALFILE]

    def write(self, data):
        """
        Write a string to the user on stdout
        """
        return self.writefn(data.encode('utf8'))

    def writeBytes(self, data):
        """
        Like write() but input is bytes
        """
        return self.writefn(data)

    def errorWrite(self, data):
        """
        Write errors to the user on stderr
        """
        return self.errorWritefn(data.encode('utf8'))

    def check_arguments(self, application, args):
        files = []
        for arg in args:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if self.fs.isdir(path):
                self.errorWrite("{}: error reading `{}': Is a directory\n".format(application, arg))
                continue
            files.append(path)
        return files

    def set_input_data(self, data):
        self.input_data = data

    def write_to_file(self, data):
        with open(self.safeoutfile, 'ab') as f:
            f.write(data)
        self.writtenBytes += len(data)
        self.fs.update_size(self.outfile, self.writtenBytes)

    def write_to_failed(self, data):
        pass

    def start(self):
        if self.write != self.write_to_failed:
            self.call()
        self.exit()

    def call(self):
        self.write(b'Hello World! [%s]\n' % (repr(self.args),))

    def exit(self):
        """
        Sometimes client is disconnected and command exits after. So cmdstack is gone
        """
        if self.protocol and self.protocol.terminal and hasattr(self, 'safeoutfile') and self.safeoutfile:
            if hasattr(self, 'outfile') and self.outfile:
                self.protocol.terminal.redirFiles.add((self.safeoutfile, self.outfile))
            else:
                self.protocol.terminal.redirFiles.add((self.safeoutfile, ''))

        if len(self.protocol.cmdstack):
            self.protocol.cmdstack.pop()
            if len(self.protocol.cmdstack):
                self.protocol.cmdstack[-1].resume()
        else:
            ret = failure.Failure(error.ProcessDone(status=""))
            # The session could be disconnected already, when his happens .transport is gone
            try:
                self.protocol.terminal.transport.processEnded(ret)
            except AttributeError:
                pass

    def handle_CTRL_C(self):
        log.msg('Received CTRL-C, exiting..')
        self.write('^C\n')
        self.exit()

    def lineReceived(self, line):
        log.msg('QUEUED INPUT: {}'.format(line))
        # FIXME: naive command parsing, see lineReceived below
        # line = "".join(line)
        self.protocol.cmdstack[0].cmdpending.append(shlex.split(line, posix=True))

    def resume(self):
        pass

    def handle_TAB(self):
        pass

    def handle_CTRL_D(self):
        pass

    def __repr__(self):
        return str(self.__class__.__name__)
