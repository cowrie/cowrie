from core.honeypot import HoneyPotCommand
from core.fstypes import *
import stat, time

class command_ls(HoneyPotCommand):

    def uid2name(self, uid):
        if uid == 0:
            return 'root'
        return uid

    def gid2name(self, gid):
        if gid == 0:
            return 'root'
        return gid

    def call(self, args):
        path = self.honeypot.cwd
        paths = []
        if len(args):
            for arg in args.split():
                if not arg.startswith('-'):
                    paths.append(self.honeypot.fs.resolve_path(arg,
                        self.honeypot.cwd))
        if not paths:
            self.do_ls_l(path)
        else:
            for path in paths:
                self.do_ls_l(path)

    def do_ls_l(self, path):
        try:
            files = self.honeypot.fs.list_files(path)
        except:
            self.honeypot.writeln(
                'ls: cannot access %s: No such file or directory' % path)
            return

        largest = 0
        if len(files):
            largest = max([x[A_SIZE] for x in files])

        for file in files:
            perms = ['-'] * 10

            if file[A_MODE] & stat.S_IRUSR: perms[1] = 'r'
            if file[A_MODE] & stat.S_IWUSR: perms[2] = 'w'
            if file[A_MODE] & stat.S_IXUSR: perms[3] = 'x'

            if file[A_MODE] & stat.S_IRGRP: perms[4] = 'r'
            if file[A_MODE] & stat.S_IWGRP: perms[5] = 'w'
            if file[A_MODE] & stat.S_IXGRP: perms[6] = 'x'

            if file[A_MODE] & stat.S_IROTH: perms[7] = 'r'
            if file[A_MODE] & stat.S_IWOTH: perms[8] = 'w'
            if file[A_MODE] & stat.S_IXOTH: perms[9] = 'x'

            if file[A_TYPE] == T_DIR:
                perms[0] = 'd'

            perms = ''.join(perms)
            ctime = time.localtime(file[A_CTIME])

            l = '%s 1 %s %s %s %s %s' % \
                (perms,
                self.uid2name(file[A_UID]),
                self.gid2name(file[A_GID]),
                str(file[A_SIZE]).rjust(len(str(largest))),
                time.strftime('%Y-%m-%d %H:%M', ctime),
                file[A_NAME])

            self.honeypot.writeln(l)

# vim: set sw=4 et:
