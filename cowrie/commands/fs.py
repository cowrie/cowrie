# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os
import getopt
import copy

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *

commands = {}

class command_cat(HoneyPotCommand):
    def start(self):
        if not self.args or self.args[0] == '>':
            pass
        else:
            for arg in self.args:
                path = self.fs.resolve_path(arg, self.protocol.cwd)
                if self.fs.isdir(path):
                    self.writeln('cat: %s: Is a directory' % (arg,))
                    continue
                try:
                    self.write(self.fs.file_contents(path))
                except:
                    self.writeln('cat: %s: No such file or directory' % (arg,))
            self.exit()

    def lineReceived(self, line):
        log.msg( eventid='KIPP0008', realm='cat', input=line,
            format='INPUT (%(realm)s): %(input)s' )

    def handle_CTRL_D(self):
        self.exit()
commands['/bin/cat'] = command_cat

class command_tail(HoneyPotCommand):
    def start(self):
        self.n = 10
        if not self.args or self.args[0] == '>':
            pass
        else:
            try:
                optlist, args = getopt.getopt(self.args, 'n:')
            except getopt.GetoptError as err:
                self.writeln("tail: invalid option -- '%s'" % (arg,))
                self.exit()
                return

            for opt in optlist:
                if opt[0] == '-n':
                    self.n = int(opt[1])

            for arg in args:
                path = self.fs.resolve_path(arg, self.protocol.cwd)
                if self.fs.isdir(path):
                    self.writeln("tail: error reading `%s': Is a directory" % (arg,))
                    continue
                try:
                    file = self.fs.file_contents(path).split('\n')
                    lines = int(len(file))
                    if lines < self.n:
                        self.n = lines - 1
                    i = 0
                    for j in range((lines - self.n - 1), lines):
                        if i < self.n:
                            self.writeln(file[j])
                        i += 1
                except:
                    self.writeln("tail: cannot open `%s' for reading: No such file or directory" % (arg,))
            self.exit()

    def lineReceived(self, line):
        log.msg( eventid='KIPP0008', realm='tail', input=line,
            format='INPUT (%(realm)s): %(input)s' )

    def handle_CTRL_D(self):
        self.exit()
commands['/bin/tail'] = command_tail


class command_head(HoneyPotCommand):
    def start(self):
        self.n = 10
        if not self.args or self.args[0] == '>':
            pass
        else:
            try:
                optlist, args = getopt.getopt(self.args, 'n:')
            except getopt.GetoptError as err:
                self.writeln("head: invalid option -- '%s'" % (arg,))
                self.exit()
                return

            for opt in optlist:
                if opt[0] == '-n':
                    self.n = int(opt[1])

            for arg in args:
                path = self.fs.resolve_path(arg, self.protocol.cwd)
                if self.fs.isdir(path):
                    self.writeln("head: error reading `%s': Is a directory" % (arg,))
                    continue
                try:
                    file = self.fs.file_contents(path).split('\n')
                    i = 0
                    for line in file:
                        if i < self.n:
                            self.writeln(line)
                        i += 1
                except:
                    self.writeln("head: cannot open `%s' for reading: No such file or directory" % (arg,))
            self.exit()

    def lineReceived(self, line):
        log.msg( eventid='KIPP0008', realm='head', input=line,
            format='INPUT (%(realm)s): %(input)s' )

    def handle_CTRL_D(self):
        self.exit()
commands['/bin/head'] = command_head


class command_cd(HoneyPotCommand):
    def call(self):
        if not self.args or self.args[0] == "~":
            path = self.protocol.user.avatar.home
        else:
            path = self.args[0]
        try:
            newpath = self.fs.resolve_path(path, self.protocol.cwd)
            inode = self.fs.getfile(newpath)
        except:
            newdir = None
        if path == "-":
            self.writeln('bash: cd: OLDPWD not set')
            return
        if inode is None or inode is False:
            self.writeln('bash: cd: %s: No such file or directory' % path)
            return
        if inode[A_TYPE] != T_DIR:
            self.writeln('bash: cd: %s: Not a directory' % path)
            return
        self.protocol.cwd = newpath
commands['cd'] = command_cd

class command_rm(HoneyPotCommand):
    def call(self):
        recursive = False
        for f in self.args:
            if f.startswith('-') and 'r' in f:
                recursive = True
        for f in self.args:
            path = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                dir = self.fs.get_path('/'.join(path.split('/')[:-1]))
            except (IndexError, FileNotFound):
                self.writeln(
                    'rm: cannot remove `%s\': No such file or directory' % f)
                continue
            basename = path.split('/')[-1]
            contents = [x for x in dir]
            for i in dir[:]:
                if i[A_NAME] == basename:
                    if i[A_TYPE] == T_DIR and not recursive:
                        self.writeln(
                            'rm: cannot remove `%s\': Is a directory' % \
                            i[A_NAME])
                    else:
                        dir.remove(i)
commands['/bin/rm'] = command_rm

class command_cp(HoneyPotCommand):
    def call(self):
        if not len(self.args):
            self.writeln("cp: missing file operand")
            self.writeln("Try `cp --help' for more information.")
            return
        try:
            optlist, args = getopt.gnu_getopt(self.args,
                '-abdfiHlLPpRrsStTuvx')
        except getopt.GetoptError as err:
            self.writeln('Unrecognized option')
            return
        recursive = False
        for opt in optlist:
            if opt[0] in ('-r', '-a', '-R'):
                recursive = True

        def resolv(path):
            return self.fs.resolve_path(path, self.protocol.cwd)

        if len(args) < 2:
            self.writeln("cp: missing destination file operand after `%s'" % \
                (self.args[0],))
            self.writeln("Try `cp --help' for more information.")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.writeln("cp: target `%s' is not a directory" % (dest,))
            return

        if dest[-1] == '/' and not self.fs.exists(resolv(dest)) and \
                not recursive:
            self.writeln(
                "cp: cannot create regular file `%s': Is a directory" % \
                (dest,))
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.writeln("cp: cannot create regular file " + \
                    "`%s': No such file or directory" % (dest,))
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.writeln(
                    "cp: cannot stat `%s': No such file or directory" % (src,))
                continue
            if not recursive and self.fs.isdir(resolv(src)):
                self.writeln("cp: omitting directory `%s'" % (src,))
                continue
            s = copy.deepcopy(self.fs.getfile(resolv(src)))
            if isdir:
                dir = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                dir = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest.rstrip('/'))
            if outfile in [x[A_NAME] for x in dir]:
                dir.remove([x for x in dir if x[A_NAME] == outfile][0])
            s[A_NAME] = outfile
            dir.append(s)
commands['/bin/cp'] = command_cp

class command_mv(HoneyPotCommand):
    def call(self):
        if not len(self.args):
            self.writeln("mv: missing file operand")
            self.writeln("Try `mv --help' for more information.")
            return

        try:
            optlist, args = getopt.gnu_getopt(self.args, '-bfiStTuv')
        except getopt.GetoptError as err:
            self.writeln('Unrecognized option')
            self.exit()

        def resolv(path):
            return self.fs.resolve_path(path, self.protocol.cwd)

        if len(args) < 2:
            self.writeln("mv: missing destination file operand after `%s'" % \
                (self.args[0],))
            self.writeln("Try `mv --help' for more information.")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.writeln("mv: target `%s' is not a directory" % (dest,))
            return

        if dest[-1] == '/' and not self.fs.exists(resolv(dest)) and \
                len(sources) != 1:
            self.writeln(
                "mv: cannot create regular file `%s': Is a directory" % \
                (dest,))
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.writeln("mv: cannot create regular file " + \
                    "`%s': No such file or directory" % \
                    (dest,))
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.writeln(
                    "mv: cannot stat `%s': No such file or directory" % \
                    (src,))
                continue
            s = self.fs.getfile(resolv(src))
            if isdir:
                dir = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                dir = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest)
            if dir != os.path.dirname(resolv(src)):
                s[A_NAME] = outfile
                dir.append(s)
                sdir = self.fs.get_path(os.path.dirname(resolv(src)))
                sdir.remove(s)
            else:
                s[A_NAME] = outfile
commands['/bin/mv'] = command_mv

class command_mkdir(HoneyPotCommand):
    def call(self):
        for f in self.args:
            path = self.fs.resolve_path(f, self.protocol.cwd)
            if self.fs.exists(path):
                self.writeln(
                    'mkdir: cannot create directory `%s\': File exists' % f)
                return
            try:
                self.fs.mkdir(path, 0, 0, 4096, 16877)
            except (FileNotFound) as err:
                self.writeln(
                    'mkdir: cannot create directory `%s\': ' % f + \
                    'No such file or directory')
            return
commands['/bin/mkdir'] = command_mkdir

class command_rmdir(HoneyPotCommand):
    def call(self):
        for f in self.args:
            path = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                if len(self.fs.get_path(path)):
                    self.writeln(
                        'rmdir: failed to remove `%s\': Directory not empty' % f)
                    continue
                dir = self.fs.get_path('/'.join(path.split('/')[:-1]))
            except (IndexError, FileNotFound):
                dir = None
            fname = os.path.basename(f)
            if not dir or fname not in [x[A_NAME] for x in dir]:
                self.writeln(
                    'rmdir: failed to remove `%s\': ' % f + \
                    'No such file or directory')
                continue
            for i in dir[:]:
                if i[A_NAME] == fname:
                    if i[A_TYPE] != T_DIR:
                        self.writeln("rmdir: failed to remove '%s': Not a directory" % f)
                        return
                    dir.remove(i)
                    break
commands['/bin/rmdir'] = command_rmdir

class command_pwd(HoneyPotCommand):
    def call(self):
        self.writeln(self.protocol.cwd)
commands['/bin/pwd'] = command_pwd

class command_touch(HoneyPotCommand):
    def call(self):
        if not len(self.args):
            self.writeln('touch: missing file operand')
            self.writeln('Try `touch --help\' for more information.')
            return
        for f in self.args:
            path = self.fs.resolve_path(f, self.protocol.cwd)
            if not self.fs.exists(os.path.dirname(path)):
                self.writeln(
                    'touch: cannot touch `%s`: no such file or directory' % \
                    (path))
                return
            if self.fs.exists(path):
                # FIXME: modify the timestamp here
                continue
            self.fs.mkfile(path, 0, 0, 0, 33188)
commands['/bin/touch'] = command_touch

# vim: set sw=4 et:
