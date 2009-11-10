import os, time
from core.Kippo import HoneyPotCommand
from core.fstypes import *

class command_whoami(HoneyPotCommand):
    def call(self, args):
        self.honeypot.writeln(self.honeypot.user.username)

class command_cat(HoneyPotCommand):
    def call(self, args):
        path = self.honeypot.fs.resolve_path(args, self.honeypot.cwd)

        if not path or not self.honeypot.fs.exists(path):
            self.honeypot.writeln(
                'bash: cat: %s: No such file or directory' % args)
            return

        fakefile = './honeyfs/%s' % path
        if os.path.exists(fakefile) and \
                not os.path.islink(fakefile) and os.path.isfile(fakefile):
            f = file(fakefile, 'r')
            self.honeypot.terminal.write(f.read())
            f.close()

class command_cd(HoneyPotCommand):
    def call(self, args):
        if not args:
            args = '/root'

        try:
            newpath = self.honeypot.fs.resolve_path(args, self.honeypot.cwd)
            newdir = self.honeypot.fs.get_path(newpath)
        except:
            newdir = None

        if newdir is None:
            self.honeypot.writeln(
                'bash: cd: %s: No such file or directory' % args)
            return
        self.honeypot.cwd = newpath

class command_rm(HoneyPotCommand):
    def call(self, args):
        for f in args.split(' '):
            path = self.honeypot.fs.resolve_path(f, self.honeypot.cwd)
            dir = self.honeypot.fs.get_path('/'.join(path.split('/')[:-1]))
            basename = path.split('/')[-1]
            contents = [x for x in dir]
            for i in dir[:]:
                if i[A_NAME] == basename:
                    if i[A_TYPE] == T_DIR:
                        self.honeypot.writeln(
                            'rm: cannot remove `%s\': Is a directory' % \
                            i[A_NAME])
                    else:
                        dir.remove(i)

class command_uptime(HoneyPotCommand):
    def call(self, args):
        self.honeypot.writeln(
            ' %s up 14 days,  3:53,  0 users,  load average: 0.08, 0.02, 0.01' % \
            time.strftime('%T'))
        #self.honeypot.writeln('USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT')

class command_w(HoneyPotCommand):
    def call(self, args):
        self.honeypot.writeln(
            ' %s up 14 days,  3:53,  0 users,  load average: 0.08, 0.02, 0.01' % \
            time.strftime('%T'))
        self.honeypot.writeln('USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT')

class command_echo(HoneyPotCommand):
    def call(self, args):
        self.honeypot.writeln(args)

class command_quit(HoneyPotCommand):
    def call(self, args):
        self.honeypot.terminal.loseConnection()

class command_clear(HoneyPotCommand):
    def call(self, args):
        self.honeypot.terminal.reset()

class command_vi(HoneyPotCommand):
    def call(self, args):
        self.honeypot.writeln('E558: Terminal entry not found in terminfo')

class command_uname(HoneyPotCommand):
    def call(self, args):
        if args.strip() == '-a':
            self.honeypot.writeln('Linux sales 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:37 UTC 2009 i686 GNU/Linux')
        else:
            self.honeypot.writeln('Linux')

class command_mount(HoneyPotCommand):
    def call(self, args):
        if len(args.strip()):
            return
        for i in [
                '/dev/sda1 on / type ext3 (rw,errors=remount-ro)',
                'tmpfs on /lib/init/rw type tmpfs (rw,nosuid,mode=0755)',
                'proc on /proc type proc (rw,noexec,nosuid,nodev)',
                'sysfs on /sys type sysfs (rw,noexec,nosuid,nodev)',
                'udev on /dev type tmpfs (rw,mode=0755)',
                'tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)',
                'devpts on /dev/pts type devpts (rw,noexec,nosuid,gid=5,mode=620)',
                ]:
            self.honeypot.writeln(i)

class command_pwd(HoneyPotCommand):
    def call(self, args):
        self.honeypot.writeln(self.honeypot.cwd)

class command_nop(HoneyPotCommand):
    def call(self, args):
        pass
