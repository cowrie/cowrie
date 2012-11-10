# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os, time, anydbm, datetime
from kippo.core.honeypot import HoneyPotCommand
from twisted.internet import reactor
from kippo.core.config import config
from kippo.core.userdb import UserDB
from kippo.core import utils

commands = {}

class command_whoami(HoneyPotCommand):
    def call(self):
        self.writeln(self.honeypot.user.username)
commands['/usr/bin/whoami'] = command_whoami

class command_uptime(HoneyPotCommand):
    def call(self):
        if len(self.args):
            secs = int(self.args[0])
            self.honeypot.uptime(time.time() - secs)
        self.writeln(' %s up %s,  1 user,  load average: 0.00, 0.00, 0.00' % \
            (time.strftime('%H:%M:%S'), utils.uptime(self.honeypot.uptime())))
commands['/usr/bin/uptime'] = command_uptime

class command_w(HoneyPotCommand):
    def call(self):
        self.writeln(' %s up %s,  1 user,  load average: 0.00, 0.00, 0.00' % \
            (time.strftime('%H:%M:%S'), utils.uptime(self.honeypot.uptime())))
        self.writeln('USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT')
        self.writeln('%-8s pts/0    %s %s    0.00s  0.00s  0.00s w' % \
            (self.honeypot.user.username,
            self.honeypot.clientIP[:17].ljust(17),
            time.strftime('%H:%M', time.localtime(self.honeypot.logintime))))
commands['/usr/bin/w'] = command_w
commands['/usr/bin/who'] = command_w

class command_echo(HoneyPotCommand):
    def call(self):
        self.writeln(' '.join(self.args))
commands['/bin/echo'] = command_echo

# for testing purposes
class command_exxxit(HoneyPotCommand):
    def call(self):
        if self.honeypot.clientIP.startswith('127.0.0.'):
            self.honeypot.terminal.loseConnection()
        else:
            self.writeln('bash: exxxit: command not found')
commands['exxxit'] = command_exxxit

class command_exit(HoneyPotCommand):
    def call(self):
        if 'PuTTY' in self.honeypot.clientVersion or \
                'libssh' in self.honeypot.clientVersion or \
                'sshlib' in self.honeypot.clientVersion:
            self.honeypot.terminal.loseConnection()
            return
        self.honeypot.terminal.reset()
        self.writeln('Connection to server closed.')
        self.honeypot.hostname = 'localhost'
        self.honeypot.cwd = '/root'
        if not self.fs.exists(self.honeypot.cwd):
            self.honeypot.cwd = '/'
commands['exit'] = command_exit
commands['logout'] = command_exit

class command_clear(HoneyPotCommand):
    def call(self):
        self.honeypot.terminal.reset()
commands['/usr/bin/clear'] = command_clear

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
        user = self.honeypot.user.username
        args = ''
        if len(self.args):
            args = self.args[0].strip()
        _user, _pid, _cpu, _mem, _vsz, _rss, _tty, _stat, \
            _start, _time, _command = range(11)
        output = (
            ('USER      ', ' PID', ' %CPU', ' %MEM', '    VSZ', '   RSS', ' TTY      ', 'STAT ', 'START', '   TIME ', 'COMMAND',),
            ('root      ', '   1', '  0.0', '  0.1', '   2100', '   688', ' ?        ', 'Ss   ', 'Nov06', '   0:07 ', 'init [2]  ',),
            ('root      ', '   2', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[kthreadd]',),
            ('root      ', '   3', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[migration/0]',),
            ('root      ', '   4', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[ksoftirqd/0]',),
            ('root      ', '   5', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[watchdog/0]',),
            ('root      ', '   6', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:17 ', '[events/0]',),
            ('root      ', '   7', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[khelper]',),
            ('root      ', '  39', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[kblockd/0]',),
            ('root      ', '  41', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[kacpid]',),
            ('root      ', '  42', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[kacpi_notify]',),
            ('root      ', ' 170', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[kseriod]',),
            ('root      ', ' 207', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S    ', 'Nov06', '   0:01 ', '[pdflush]',),
            ('root      ', ' 208', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S    ', 'Nov06', '   0:00 ', '[pdflush]',),
            ('root      ', ' 209', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[kswapd0]',),
            ('root      ', ' 210', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[aio/0]',),
            ('root      ', ' 748', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[ata/0]',),
            ('root      ', ' 749', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[ata_aux]',),
            ('root      ', ' 929', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[scsi_eh_0]',),
            ('root      ', '1014', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'D<   ', 'Nov06', '   0:03 ', '[kjournald]',),
            ('root      ', '1087', '  0.0', '  0.1', '   2288', '   772', ' ?        ', 'S<s  ', 'Nov06', '   0:00 ', 'udevd --daemon',),
            ('root      ', '1553', '  0.0', '  0.0', '      0', '     0', ' ?        ', 'S<   ', 'Nov06', '   0:00 ', '[kpsmoused]',),
            ('root      ', '2054', '  0.0', '  0.2', '  28428', '  1508', ' ?        ', 'Sl   ', 'Nov06', '   0:01 ', '/usr/sbin/rsyslogd -c3',),
            ('root      ', '2103', '  0.0', '  0.2', '   2628', '  1196', ' tty1     ', 'Ss   ', 'Nov06', '   0:00 ', '/bin/login --     ',),
            ('root      ', '2105', '  0.0', '  0.0', '   1764', '   504', ' tty2     ', 'Ss+  ', 'Nov06', '   0:00 ', '/sbin/getty 38400 tty2',),
            ('root      ', '2107', '  0.0', '  0.0', '   1764', '   504', ' tty3     ', 'Ss+  ', 'Nov06', '   0:00 ', '/sbin/getty 38400 tty3',),
            ('root      ', '2109', '  0.0', '  0.0', '   1764', '   504', ' tty4     ', 'Ss+  ', 'Nov06', '   0:00 ', '/sbin/getty 38400 tty4',),
            ('root      ', '2110', '  0.0', '  0.0', '   1764', '   504', ' tty5     ', 'Ss+  ', 'Nov06', '   0:00 ', '/sbin/getty 38400 tty5',),
            ('root      ', '2112', '  0.0', '  0.0', '   1764', '   508', ' tty6     ', 'Ss+  ', 'Nov06', '   0:00 ', '/sbin/getty 38400 tty6',),
            ('root      ', '2133', '  0.0', '  0.1', '   2180', '   620', ' ?        ', 'S<s  ', 'Nov06', '   0:00 ', 'dhclient3 -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp3/dhclien',),
            ('root      ', '4969', '  0.0', '  0.1', '   5416', '  1024', ' ?        ', 'Ss   ', 'Nov08', '   0:00 ', '/usr/sbin/sshd: %s@pts/0' % user,),
            ('%s'.ljust(8) % user, '5673', '  0.0', '  0.2', '   2924', '  1540', ' pts/0    ', 'Ss   ', '04:30', '   0:00 ', '-bash',),
            ('%s'.ljust(8) % user, '5679', '  0.0', '  0.1', '   2432', '   928', ' pts/0    ', 'R+   ', '04:32', '   0:00 ', 'ps %s' % ' '.join(self.args),)
            )
        for i in range(len(output)):
            if i != 0:
                if 'a' not in args and output[i][_user].strip() != user:
                    continue
                elif 'a' not in args and 'x' not in args \
                        and output[i][_tty].strip() != 'pts/0':
                    continue
            l = [_pid, _tty, _time, _command]
            if 'a' in args or 'x' in args:
                l = [_pid, _tty, _stat, _time, _command]
            if 'u' in args:
                l = [_user, _pid, _cpu, _mem, _vsz, _rss, _tty, _stat,
                    _start, _time, _command]
            s = ''.join([output[i][x] for x in l])
            if 'w' not in args:
                s = s[:80]
            self.writeln(s)
commands['/bin/ps'] = command_ps

class command_id(HoneyPotCommand):
    def call(self):
        u = self.honeypot.user
        self.writeln('uid=%d(%s) gid=%d(%s) groups=%d(%s)' % \
            (u.uid, u.username, u.gid, u.username, u.gid, u.username))
commands['/usr/bin/id'] = command_id

class command_passwd(HoneyPotCommand):
    def start(self):
        self.write('Enter new UNIX password: ')
        self.honeypot.password_input = True
        self.callbacks = [self.ask_again, self.finish]
        self.passwd = None

    def ask_again(self, line):
        self.passwd = line
        self.write('Retype new UNIX password: ')

    def finish(self, line):
        self.honeypot.password_input = False

        if line != self.passwd:
            self.writeln('Sorry, passwords do not match')
            self.exit()
            return

        userdb = UserDB()
        userdb.adduser(self.honeypot.user.username,
            self.honeypot.user.uid, self.passwd)

        self.writeln('passwd: password updated successfully')
        self.exit()

    def lineReceived(self, line):
        print 'INPUT (passwd):', line
        self.password = line.strip()
        self.callbacks.pop(0)(line)
commands['/usr/bin/passwd'] = command_passwd

class command_shutdown(HoneyPotCommand):
    def start(self):
        if len(self.args) and self.args[0].strip().count('--help'):
            output = (
                "Usage:     shutdown [-akrhHPfnc] [-t secs] time [warning message]",
                "-a:      use /etc/shutdown.allow ",
                "-k:      don't really shutdown, only warn. " ,
                "-r:      reboot after shutdown. " ,
                "-h:      halt after shutdown. " ,  
                "-P:      halt action is to turn off power. " ,
                "-H:      halt action is to just halt. " ,
                "-f:      do a 'fast' reboot (skip fsck). " ,
                "-F:      Force fsck on reboot. " ,
                "-n:      do not go through \"init\" but go down real fast. " ,
                "-c:      cancel a running shutdown. " ,
                "-t secs: delay between warning and kill signal. " ,
                "** the \"time\" argument is mandatory! (try \"now\") **",
                )
            for l in output:
                self.writeln(l)
            self.exit()
        elif len(self.args) > 1 and self.args[0].strip().count('-h') \
                and self.args[1].strip().count('now'):
            self.nextLine()
            self.writeln(  
                'Broadcast message from root@%s (pts/0) (%s):' % \
                (self.honeypot.hostname, time.ctime()))
            self.nextLine()
            self.writeln('The system is going down for maintenance NOW!')
            reactor.callLater(3, self.finish)
        elif len(self.args) > 1 and self.args[0].strip().count('-r') \
                and self.args[1].strip().count('now'):
            self.nextLine()
            self.writeln(  
                'Broadcast message from root@%s (pts/0) (%s):' % \
                (self.honeypot.hostname, time.ctime()))
            self.nextLine()
            self.writeln('The system is going down for reboot NOW!')
            reactor.callLater(3, self.finish)
        else:
            self.writeln("Try `shutdown --help' for more information.")
            self.exit()
            return
            
    def finish(self):
        self.writeln('Connection to server closed.')
        self.honeypot.hostname = 'localhost'
        self.honeypot.cwd = '/root'
        if not self.fs.exists(self.honeypot.cwd):
            self.honeypot.cwd = '/'
        self.exit()
commands['/sbin/shutdown'] = command_shutdown

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
        self.honeypot.cwd = '/root'
        if not self.fs.exists(self.honeypot.cwd):
            self.honeypot.cwd = '/'
        self.honeypot.uptime(time.time())
        self.exit()
commands['/sbin/reboot'] = command_reboot

class command_history(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0] == '-c':
            self.honeypot.historyLines = []
            self.honeypot.historyPosition = 0
            return
        count = 1
        for l in self.honeypot.historyLines:
            self.writeln(' %s  %s' % (str(count).rjust(4), l))
            count += 1
commands['history'] = command_history

class command_date(HoneyPotCommand):
    def call(self):
        time = datetime.datetime.utcnow();
        self.writeln(time.strftime("%a %b %d %H:%M:%S UTC %Y"))
commands['/bin/date'] = command_date

class command_yes(HoneyPotCommand):
    def start(self):
        self.y()

    def y(self):
        self.writeln('y')
        self.scheduled = reactor.callLater(0.01, self.y)

    def ctrl_c(self):
        self.scheduled.cancel()
        self.exit()
commands['/usr/bin/yes'] = command_yes

class command_nop(HoneyPotCommand):
    def call(self):
        pass
commands['/bin/chmod'] = command_nop
commands['set'] = command_nop
commands['unset'] = command_nop
commands['export'] = command_nop
commands['/bin/bash'] = command_nop
commands['/bin/sh'] = command_nop
commands['/bin/kill'] = command_nop
commands['/bin/su'] = command_nop

# vim: set sw=4 et:
