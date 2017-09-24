# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import division, absolute_import

import stat
import getopt
import time

from cowrie.shell.honeypot import HoneyPotCommand
from cowrie.shell.fs import *
from cowrie.shell.pwd import Passwd, Group

commands = {}

class command_ls(HoneyPotCommand):
    """
    """

    def uid2name(self, uid):
        """
        """
        try:
            return Passwd(self.protocol.cfg).getpwuid(uid)["pw_name"]
        except:
            return str(uid)


    def gid2name(self, gid):
        """
        """
        try:
            return Group(self.protocol.cfg).getgrgid(gid)["gr_name"]
        except:
            return str(gid)


    def call(self):
        """
        """
        path = self.protocol.cwd
        paths = []
        self.showHidden = False
        self.showDirectories = False
        func = self.do_ls_normal

        # Parse options or display no files
        try:
            opts, args = getopt.gnu_getopt(self.args, '1@ABCFGHLOPRSTUWabcdefghiklmnopqrstuvwx', ['help', 'version', 'param'])
        except getopt.GetoptError as err:
            self.write("ls: {}\n".format(err))
            self.write("Try 'ls --help' for more information.\n")
            return

        for x, a in opts:
            if x in ('-l'):
                func = self.do_ls_l
            if x in ('-a'):
                self.showHidden = True
            if x in ('-d'):
                self.showDirectories = True

        for arg in args:
            paths.append(self.protocol.fs.resolve_path(arg, self.protocol.cwd))

        if not paths:
            func(path)
        else:
            for path in paths:
                func(path)


    def do_ls_normal(self, path):
        """
        """
        try:
            if self.protocol.fs.isdir(path) and self.showDirectories == False:
                files = self.protocol.fs.get_path(path)[:]
                if self.showHidden:
                    dot = self.protocol.fs.getfile(path)[:]
                    dot[A_NAME] = '.'
                    files.append(dot)
                    # FIXME: should grab dotdot off the parent instead
                    dotdot = self.protocol.fs.getfile(path)[:]
                    dotdot[A_NAME] = '..'
                    files.append(dotdot)
                else:
                    files = [x for x in files if not x[A_NAME].startswith('.')]
                files.sort()
            else:
                files = (self.protocol.fs.getfile(path)[:],)
        except:
            self.write(
                'ls: cannot access %s: No such file or directory\n' % (path,))
            return

        l = [x[A_NAME] for x in files]
        if not l:
            return
        count = 0
        maxlen = max([len(x) for x in l])

        try:
            wincols = self.protocol.user.windowSize[1]
        except AttributeError:
            wincols = 80

        perline = int(wincols / (maxlen + 1))
        for f in l:
            if count == perline:
                count = 0
                self.write('\n')
            self.write(f.ljust(maxlen + 1))
            count += 1
        self.write('\n')


    def do_ls_l(self, path):
        """
        """
        try:
            if self.protocol.fs.isdir(path) and self.showDirectories == False:
                files = self.protocol.fs.get_path(path)[:]
                if self.showHidden:
                    dot = self.protocol.fs.getfile(path)[:]
                    dot[A_NAME] = '.'
                    files.append(dot)
                    # FIXME: should grab dotdot off the parent instead
                    dotdot = self.protocol.fs.getfile(path)[:]
                    dotdot[A_NAME] = '..'
                    files.append(dotdot)
                else:
                    files = [x for x in files if not x[A_NAME].startswith('.')]
                files.sort()
            else:
                files = (self.protocol.fs.getfile(path)[:],)
        except:
            self.write(
                'ls: cannot access %s: No such file or directory\n' % (path,))
            return

        largest = 0
        if len(files):
            largest = max([x[A_SIZE] for x in files])

        for file in files:
            if file[A_NAME].startswith('.') and not self.showHidden:
                continue

            perms = ['-'] * 10
            if file[A_MODE] & stat.S_IRUSR: perms[1] = 'r'
            if file[A_MODE] & stat.S_IWUSR: perms[2] = 'w'
            if file[A_MODE] & stat.S_IXUSR: perms[3] = 'x'
            if file[A_MODE] & stat.S_ISUID: perms[3] = 'S'
            if file[A_MODE] & stat.S_IXUSR and file[A_MODE] & stat.S_ISUID: perms[3] = 's'

            if file[A_MODE] & stat.S_IRGRP: perms[4] = 'r'
            if file[A_MODE] & stat.S_IWGRP: perms[5] = 'w'
            if file[A_MODE] & stat.S_IXGRP: perms[6] = 'x'
            if file[A_MODE] & stat.S_ISGID: perms[6] = 'S'
            if file[A_MODE] & stat.S_IXGRP and file[A_MODE] & stat.S_ISGID: perms[6] = 's'

            if file[A_MODE] & stat.S_IROTH: perms[7] = 'r'
            if file[A_MODE] & stat.S_IWOTH: perms[8] = 'w'
            if file[A_MODE] & stat.S_IXOTH: perms[9] = 'x'
            if file[A_MODE] & stat.S_ISVTX: perms[9] = 'T'
            if file[A_MODE] & stat.S_IXOTH and file[A_MODE] & stat.S_ISVTX: perms[9] = 't'

            linktarget = ''

            if file[A_TYPE] == T_DIR:
                perms[0] = 'd'
            elif file[A_TYPE] == T_LINK:
                perms[0] = 'l'
                linktarget = ' -> %s' % (file[A_TARGET],)

            perms = ''.join(perms)
            ctime = time.localtime(file[A_CTIME])

            l = '%s 1 %s %s %s %s %s%s' % \
                (perms,
                self.uid2name(file[A_UID]),
                self.gid2name(file[A_GID]),
                str(file[A_SIZE]).rjust(len(str(largest))),
                time.strftime('%Y-%m-%d %H:%M', ctime),
                file[A_NAME],
                linktarget)

            self.write(l+'\n')
commands['/bin/ls'] = command_ls
commands['/bin/dir'] = command_ls

