# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os, time
from kippo.core.honeypot import HoneyPotCommand
from kippo.core.fs import *
from twisted.internet import reactor
from kippo.core.config import config

commands = {}

class command_whoami(HoneyPotCommand):
    def call(self):
        self.writeln(self.honeypot.user.username)
commands['/usr/bin/whoami'] = command_whoami

class command_cat(HoneyPotCommand):
    def call(self):
        for arg in self.args:
            path = self.fs.resolve_path(arg, self.honeypot.cwd)
            if not path or not self.fs.exists(path):
                self.writeln('bash: cat: %s: No such file or directory' % arg)
                return
            f = self.fs.getfile(path)

            realfile = self.fs.realfile(f,
                '%s/%s' % (config().get('honeypot', 'contents_path'), path))
            if realfile:
                f = file(realfile, 'rb')
                self.write(f.read())
                f.close()
commands['/bin/cat'] = command_cat

class command_cd(HoneyPotCommand):
    def call(self):
        if not self.args:
            path = '/root'
        else:
            path = self.args[0]
        try:
            newpath = self.fs.resolve_path(path, self.honeypot.cwd)
            newdir = self.fs.get_path(newpath)
        except IndexError:
            newdir = None
        if newdir is None:
            self.writeln('bash: cd: %s: No such file or directory' % path)
            return
        if not self.fs.is_dir(newpath):
            self.writeln('-bash: cd: %s: Not a directory' % path)
            return
        self.honeypot.cwd = newpath
commands['cd'] = command_cd

class command_rm(HoneyPotCommand):
    def call(self):
        recursive = False
        for f in self.args:
            if f.startswith('-') and 'r' in f:
                recursive = True
        for f in self.args:
            path = self.fs.resolve_path(f, self.honeypot.cwd)
            try:
                dir = self.fs.get_path('/'.join(path.split('/')[:-1]))
            except IndexError:
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

class command_mkdir(HoneyPotCommand):
    def call(self):
        for f in self.args:
            path = self.fs.resolve_path(f, self.honeypot.cwd)
            if self.fs.exists(path):
                self.writeln(
                    'mkdir: cannot create directory `%s\': File exists' % f)
                return
            ok = self.fs.mkdir(path, 0, 0, 4096, 16877)
            if not ok:
                self.writeln(
                    'mkdir: cannot create directory `%s\': ' % f + \
                    'No such file or directory')
                return
commands['/bin/mkdir'] = command_mkdir

class command_rmdir(HoneyPotCommand):
    def call(self):
        for f in self.args:
            path = self.fs.resolve_path(f, self.honeypot.cwd)
            if len(self.fs.get_path(path)):
                self.writeln(
                    'rmdir: failed to remove `%s\': Directory not empty' % f)
                continue
            try:
                dir = self.fs.get_path('/'.join(path.split('/')[:-1]))
            except IndexError:
                dir = None
            if not dir or f not in [x[A_NAME] for x in dir]:
                self.writeln(
                    'rmdir: failed to remove `%s\': ' % f + \
                    'No such file or directory')
                continue
            for i in dir[:]:
                if i[A_NAME] == f:
                    dir.remove(i)
commands['/bin/rmdir'] = command_rmdir

class command_uptime(HoneyPotCommand):
    def call(self):
        self.writeln(' %s up 14 days,  3:53,  0 users,  load average: 0.08, 0.02, 0.01' % \
            time.strftime('%H:%M:%S'))
commands['/usr/bin/uptime'] = command_uptime

class command_w(HoneyPotCommand):
    def call(self):
        self.writeln(' %s up 14 days,  3:53,  1 user,  load average: 0.08, 0.02, 0.01' % \
            time.strftime('%H:%M:%S'))
        self.writeln('USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT')
        self.writeln('root     pts/0    %s %s    0.00s  0.00s  0.00s w' % \
            (self.honeypot.clientIP[:17].ljust(17),
            time.strftime('%H:%M', time.localtime(self.honeypot.logintime))))
commands['/usr/bin/w'] = command_w
commands['/usr/bin/who'] = command_w

class command_echo(HoneyPotCommand):
    def call(self):
        self.writeln(' '.join(self.args))
commands['/bin/echo'] = command_echo

class command_exit(HoneyPotCommand):
    def call(self):
        #self.honeypot.terminal.loseConnection()
        self.honeypot.terminal.reset()
        self.writeln('Connection to server closed.')
        self.honeypot.hostname = 'localhost'
        self.honeypot.cwd = '/root'
commands['exit'] = command_exit

class command_clear(HoneyPotCommand):
    def call(self):
        self.honeypot.terminal.reset()
commands['/usr/bin/clear'] = command_clear

class command_vi(HoneyPotCommand):
    def call(self):
        self.writeln('E558: Terminal entry not found in terminfo')
commands['/usr/bin/vi'] = command_vi

class command_hostname(HoneyPotCommand):
    def call(self):
        self.writeln(self.honeypot.hostname)
commands['/bin/hostname'] = command_hostname

class command_uname(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0].strip() == '-a':
            self.writeln(
                'Linux %s 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:37 UTC 2009 i686 GNU/Linux' % \
                self.honeypot.hostname)
        else:
            self.writeln('Linux')
commands['/bin/uname'] = command_uname

class command_ps(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0].strip().count('a'):
            output = (
                'USER       PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND',
                'root         1  0.0  0.1   2100   688 ?        Ss   Nov06   0:07 init [2]  ',
                'root         2  0.0  0.0      0     0 ?        S<   Nov06   0:00 [kthreadd]',
                'root         3  0.0  0.0      0     0 ?        S<   Nov06   0:00 [migration/0]',
                'root         4  0.0  0.0      0     0 ?        S<   Nov06   0:00 [ksoftirqd/0]',
                'root         5  0.0  0.0      0     0 ?        S<   Nov06   0:00 [watchdog/0]',
                'root         6  0.0  0.0      0     0 ?        S<   Nov06   0:17 [events/0]',
                'root         7  0.0  0.0      0     0 ?        S<   Nov06   0:00 [khelper]',
                'root        39  0.0  0.0      0     0 ?        S<   Nov06   0:00 [kblockd/0]',
                'root        41  0.0  0.0      0     0 ?        S<   Nov06   0:00 [kacpid]',
                'root        42  0.0  0.0      0     0 ?        S<   Nov06   0:00 [kacpi_notify]',
                'root       170  0.0  0.0      0     0 ?        S<   Nov06   0:00 [kseriod]',
                'root       207  0.0  0.0      0     0 ?        S    Nov06   0:01 [pdflush]',
                'root       208  0.0  0.0      0     0 ?        S    Nov06   0:00 [pdflush]',
                'root       209  0.0  0.0      0     0 ?        S<   Nov06   0:00 [kswapd0]',
                'root       210  0.0  0.0      0     0 ?        S<   Nov06   0:00 [aio/0]',
                'root       748  0.0  0.0      0     0 ?        S<   Nov06   0:00 [ata/0]',
                'root       749  0.0  0.0      0     0 ?        S<   Nov06   0:00 [ata_aux]',
                'root       929  0.0  0.0      0     0 ?        S<   Nov06   0:00 [scsi_eh_0]',
                'root      1014  0.0  0.0      0     0 ?        D<   Nov06   0:03 [kjournald]',
                'root      1087  0.0  0.1   2288   772 ?        S<s  Nov06   0:00 udevd --daemon',
                'root      1553  0.0  0.0      0     0 ?        S<   Nov06   0:00 [kpsmoused]',
                'root      2054  0.0  0.2  28428  1508 ?        Sl   Nov06   0:01 /usr/sbin/rsyslogd -c3',
                'root      2103  0.0  0.2   2628  1196 tty1     Ss   Nov06   0:00 /bin/login --     ',
                'root      2105  0.0  0.0   1764   504 tty2     Ss+  Nov06   0:00 /sbin/getty 38400 tty2',
                'root      2107  0.0  0.0   1764   504 tty3     Ss+  Nov06   0:00 /sbin/getty 38400 tty3',
                'root      2109  0.0  0.0   1764   504 tty4     Ss+  Nov06   0:00 /sbin/getty 38400 tty4',
                'root      2110  0.0  0.0   1764   504 tty5     Ss+  Nov06   0:00 /sbin/getty 38400 tty5',
                'root      2112  0.0  0.0   1764   508 tty6     Ss+  Nov06   0:00 /sbin/getty 38400 tty6',
                'root      2133  0.0  0.1   2180   620 ?        S<s  Nov06   0:00 dhclient3 -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp3/dhclien',
                'root      4969  0.0  0.1   5416  1024 ?        Ss   Nov08   0:00 /usr/sbin/sshd',
                'root      5673  0.0  0.2   2924  1540 pts/0    Ss   04:30   0:00 -bash',
                'root      5679  0.0  0.1   2432   928 pts/0    R+   04:32   0:00 ps %s' % ' '.join(self.args),
                )
        else:
            output = (
                '  PID TTY          TIME CMD',
                ' 5673 pts/0    00:00:00 bash',
                ' 5677 pts/0    00:00:00 ps %s' % ' '.join(self.args),
                )
        for l in output:
            self.writeln(l)
commands['/bin/ps'] = command_ps

class command_id(HoneyPotCommand):
    def call(self):
        self.writeln('uid=0(root) gid=0(root) groups=0(root)')
commands['/usr/bin/id'] = command_id

class command_mount(HoneyPotCommand):
    def call(self):
        if self.args and len(self.args[0].strip()):
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
            self.writeln(i)
commands['/usr/mount'] = command_mount

class command_pwd(HoneyPotCommand):
    def call(self):
        self.writeln(self.honeypot.cwd)
commands['/bin/pwd'] = command_pwd

class command_passwd(HoneyPotCommand):
    def start(self):
        self.write('Enter new UNIX password: ')
        self.honeypot.password_input = True
        self.callbacks = [self.ask_again, self.finish]

    def ask_again(self):
        self.write('Retype new UNIX password: ')

    def finish(self):
        self.honeypot.password_input = False
        self.writeln('Sorry, passwords do not match')
        self.writeln(
            'passwd: Authentication information cannot be recovered')
        self.writeln('passwd: password unchanged')
        self.exit()

    def lineReceived(self, line):
        print 'INPUT (passwd):', line
        self.callbacks.pop(0)()
commands['/usr/bin/passwd'] = command_passwd

class command_reboot(HoneyPotCommand):
    def start(self):
        self.nextLine()
        self.writeln(
            'Broadcast message from root@%s (pts/0) (%s):' % \
            (self.honeypot.hostname, time.ctime()))
        self.nextLine()
        self.writeln('The system is going down for reboot NOW!')
        reactor.callLater(3, self.finish)

    def finish(self):
        self.writeln('Connection to server closed.')
        self.honeypot.hostname = 'localhost'
        self.exit()

commands['/sbin/reboot'] = command_reboot

class command_nop(HoneyPotCommand):
    def call(self):
        pass
commands['/bin/chmod'] = command_nop
commands['set'] = command_nop
commands['unset'] = command_nop
commands['history'] = command_nop
commands['export'] = command_nop
commands['/bin/bash'] = command_nop
commands['/bin/sh'] = command_nop
commands['/bin/kill'] = command_nop

# vim: set sw=4 et:
