# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import time
import datetime
import functools
import getopt

from twisted.internet import reactor
from twisted.python import log

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.auth import UserDB
from cowrie.core import utils

commands = {}

class command_whoami(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        self.writeln(self.protocol.user.username)
commands['/usr/bin/whoami'] = command_whoami
commands['/usr/bin/users'] = command_whoami



class command_uptime(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        if len(self.args):
            secs = int(self.args[0])
            self.protocol.uptime(time.time() - secs)
        self.writeln(' %s up %s,  1 user,  load average: 0.00, 0.00, 0.00' % \
            (time.strftime('%H:%M:%S'), utils.uptime(self.protocol.uptime())))
commands['/usr/bin/uptime'] = command_uptime



class command_help(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        self.writeln("""GNU bash, version 4.2.37(1)-release (x86_64-pc-linux-gnu)
These shell commands are defined internally.  Type `help' to see this list.
Type `help name' to find out more about the function `name'.
Use `info bash' to find out more about the shell in general.
Use `man -k' or `info' to find out more about commands not in this list.

A star (*) next to a name means that the command is disabled.

 job_spec [&]                                                                                   history [-c] [-d offset] [n] or history -anrw [filename] or history -ps arg [arg...]
 (( expression ))                                                                               if COMMANDS; then COMMANDS; [ elif COMMANDS; then COMMANDS; ]... [ else COMMANDS; ] fi
 . filename [arguments]                                                                         jobs [-lnprs] [jobspec ...] or jobs -x command [args]
 :                                                                                              kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]
 [ arg... ]                                                                                     let arg [arg ...]
 [[ expression ]]                                                                               local [option] name[=value] ...
 alias [-p] [name[=value] ... ]                                                                 logout [n]
 bg [job_spec ...]                                                                              mapfile [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]
 bind [-lpvsPVS] [-m keymap] [-f filename] [-q name] [-u name] [-r keyseq] [-x keyseq:shell-c>  popd [-n] [+N | -N]
 break [n]                                                                                      printf [-v var] format [arguments]
 builtin [shell-builtin [arg ...]]                                                              pushd [-n] [+N | -N | dir]
 caller [expr]                                                                                  pwd [-LP]
 case WORD in [PATTERN [| PATTERN]...) COMMANDS ;;]... esac                                     read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout>
 cd [-L|[-P [-e]]] [dir]                                                                        readarray [-n count] [-O origin] [-s count] [-t] [-u fd] [-C callback] [-c quantum] [array]>
 command [-pVv] command [arg ...]                                                               readonly [-aAf] [name[=value] ...] or readonly -p
 compgen [-abcdefgjksuv] [-o option]  [-A action] [-G globpat] [-W wordlist]  [-F function] [>  return [n]
 complete [-abcdefgjksuv] [-pr] [-DE] [-o option] [-A action] [-G globpat] [-W wordlist]  [-F>  select NAME [in WORDS ... ;] do COMMANDS; done
 compopt [-o|+o option] [-DE] [name ...]                                                        set [-abefhkmnptuvxBCHP] [-o option-name] [--] [arg ...]
 continue [n]                                                                                   shift [n]
 coproc [NAME] command [redirections]                                                           shopt [-pqsu] [-o] [optname ...]
 declare [-aAfFgilrtux] [-p] [name[=value] ...]                                                 source filename [arguments]
 dirs [-clpv] [+N] [-N]                                                                         suspend [-f]
 disown [-h] [-ar] [jobspec ...]                                                                test [expr]
 echo [-neE] [arg ...]                                                                          time [-p] pipeline
 enable [-a] [-dnps] [-f filename] [name ...]                                                   times
 eval [arg ...]                                                                                 trap [-lp] [[arg] signal_spec ...]
 exec [-cl] [-a name] [command [arguments ...]] [redirection ...]                               true
 exit [n]                                                                                       type [-afptP] name [name ...]
 export [-fn] [name[=value] ...] or export -p                                                   typeset [-aAfFgilrtux] [-p] name[=value] ...
 false                                                                                          ulimit [-SHacdefilmnpqrstuvx] [limit]
 fc [-e ename] [-lnr] [first] [last] or fc -s [pat=rep] [command]                               umask [-p] [-S] [mode]
 fg [job_spec]                                                                                  unalias [-a] name [name ...]
 for NAME [in WORDS ... ] ; do COMMANDS; done                                                   unset [-f] [-v] [name ...]
 for (( exp1; exp2; exp3 )); do COMMANDS; done                                                  until COMMANDS; do COMMANDS; done
 function name { COMMANDS ; } or name () { COMMANDS ; }                                         variables - Names and meanings of some shell variables
 getopts optstring name [arg]                                                                   wait [id]
 hash [-lr] [-p pathname] [-dt] [name ...]                                                      while COMMANDS; do COMMANDS; done
 help [-dms] [pattern ...]                                                                      { COMMANDS ; }""")
commands['help'] = command_help



class command_w(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        self.writeln(' %s up %s,  1 user,  load average: 0.00, 0.00, 0.00' % \
            (time.strftime('%H:%M:%S'), utils.uptime(self.protocol.uptime())))
        self.writeln('USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT')
        self.writeln('%-8s pts/0    %s %s    0.00s  0.00s  0.00s w' % \
            (self.protocol.user.username,
            self.protocol.clientIP[:17].ljust(17),
            time.strftime('%H:%M', time.localtime(self.protocol.logintime))))
commands['/usr/bin/w'] = command_w



class command_who(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        self.writeln('%-8s pts/0        %s %s (%s)' % \
            (self.protocol.user.username,
            time.strftime('%Y-%m-%d', time.localtime(self.protocol.logintime)),
            time.strftime('%H:%M', time.localtime(self.protocol.logintime)),
            self.protocol.clientIP))
commands['/usr/bin/who'] = command_who



class command_echo(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        write_fn = self.writeln
        escape_fn = lambda s: s
        optlist, args = getopt.getopt(self.args, "eEn")

        for opt in optlist:
            if opt[0] == '-e':
                escape_fn = functools.partial(str.decode, encoding="string_escape")
            elif opt[0] == '-E':
                escape_fn = lambda s: s
            elif opt[0] == '-n':
                write_fn = self.write

        write_fn(escape_fn(' '.join(args)))

commands['/bin/echo'] = command_echo



class command_exit(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        self.protocol.terminal.loseConnection()
        return


    def exit(self):
        """
        """
        pass
commands['exit'] = command_exit
commands['logout'] = command_exit



class command_clear(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        self.protocol.terminal.reset()
commands['/usr/bin/clear'] = command_clear
commands['/usr/bin/reset'] = command_clear



class command_hostname(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        self.writeln(self.protocol.hostname)
commands['/bin/hostname'] = command_hostname



class command_ps(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        user = self.protocol.user.username
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
    """
    """
    def call(self):
        """
        """
        u = self.protocol.user
        self.writeln('uid=%d(%s) gid=%d(%s) groups=%d(%s)' % \
            (u.uid, u.username, u.gid, u.username, u.gid, u.username))
commands['/usr/bin/id'] = command_id



class command_passwd(HoneyPotCommand):
    """
    """
    def start(self):
        """
        """
        self.write('Enter new UNIX password: ')
        self.protocol.password_input = True
        self.callbacks = [self.ask_again, self.finish]
        self.passwd = None


    def ask_again(self, line):
        """
        """
        self.passwd = line
        self.write('Retype new UNIX password: ')


    def finish(self, line):
        """
        """
        self.protocol.password_input = False

        if line != self.passwd or self.passwd == '*':
            self.writeln('Sorry, passwords do not match')
            self.exit()
            return

        userdb = UserDB(self.protocol.cfg)
        userdb.adduser(self.protocol.user.username, self.passwd)

        self.writeln('passwd: password updated successfully')
        self.exit()


    def lineReceived(self, line):
        """
        """
        log.msg( eventid='KIPP0008', realm='passwd', input=line,
            format='INPUT (%(realm)s): %(input)s' )
        self.password = line.strip()
        self.callbacks.pop(0)(line)
commands['/usr/bin/passwd'] = command_passwd



class command_shutdown(HoneyPotCommand):
    """
    """
    def start(self):
        """
        """
        if len(self.args) and self.args[0].strip().count('--help'):
            output = (
                "Usage:     shutdown [-akrhHPfnc] [-t secs] time [warning message]",
                "-a:      use /etc/shutdown.allow ",
                "-k:      don't really shutdown, only warn. ",
                "-r:      reboot after shutdown. ",
                "-h:      halt after shutdown. ",
                "-P:      halt action is to turn off power. ",
                "-H:      halt action is to just halt. ",
                "-f:      do a 'fast' reboot (skip fsck). ",
                "-F:      Force fsck on reboot. ",
                "-n:      do not go through \"init\" but go down real fast. ",
                "-c:      cancel a running shutdown. ",
                "-t secs: delay between warning and kill signal. ",
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
                (self.protocol.hostname, time.ctime()))
            self.nextLine()
            self.writeln('The system is going down for maintenance NOW!')
            reactor.callLater(3, self.finish)
        elif len(self.args) > 1 and self.args[0].strip().count('-r') \
                and self.args[1].strip().count('now'):
            self.nextLine()
            self.writeln(
                'Broadcast message from root@%s (pts/0) (%s):' % \
                (self.protocol.hostname, time.ctime()))
            self.nextLine()
            self.writeln('The system is going down for reboot NOW!')
            reactor.callLater(3, self.finish)
        else:
            self.writeln("Try `shutdown --help' for more information.")
            self.exit()
            return


    def finish(self):
        """
        """
        self.writeln('Connection to server closed.')
        self.protocol.hostname = 'localhost'
        self.protocol.cwd = '/root'
        if not self.fs.exists(self.protocol.cwd):
            self.protocol.cwd = '/'
        self.exit()
commands['/sbin/shutdown'] = command_shutdown
commands['/sbin/poweroff'] = command_shutdown
commands['/sbin/reboot'] = command_shutdown
commands['/sbin/halt'] = command_shutdown



class command_reboot(HoneyPotCommand):
    """
    """
    def start(self):
        """
        """
        self.nextLine()
        self.writeln(
            'Broadcast message from root@%s (pts/0) (%s):' % \
            (self.protocol.hostname, time.ctime()))
        self.nextLine()
        self.writeln('The system is going down for reboot NOW!')
        reactor.callLater(3, self.finish)


    def finish(self):
        """
        """
        self.writeln('Connection to server closed.')
        self.protocol.hostname = 'localhost'
        self.protocol.cwd = '/root'
        if not self.fs.exists(self.protocol.cwd):
            self.protocol.cwd = '/'
        self.protocol.uptime(time.time())
        self.exit()
commands['/sbin/reboot'] = command_reboot



class command_history(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        try:
            if len(self.args) and self.args[0] == '-c':
                self.protocol.historyLines = []
                self.protocol.historyPosition = 0
                return
            count = 1
            for l in self.protocol.historyLines:
                self.writeln(' %s  %s' % (str(count).rjust(4), l))
                count += 1
        except:
            # Non-interactive shell, do nothing
            pass
commands['history'] = command_history



class command_date(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        time = datetime.datetime.utcnow();
        self.writeln(time.strftime("%a %b %d %H:%M:%S UTC %Y"))
commands['/bin/date'] = command_date



class command_yes(HoneyPotCommand):
    """
    """
    def start(self):
        """
        """
        self.y()


    def y(self):
        """
        """
        self.writeln('y')
        self.scheduled = reactor.callLater(0.01, self.y)


    def handle_CTRL_C(self):
        """
        """
        self.scheduled.cancel()
        self.exit()
commands['/usr/bin/yes'] = command_yes



class command_sh(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        if len(self.args) and self.args[0].strip() == '-c':
            self.protocol.cmdstack[0].cmdpending.append(
                ' '.join(self.args[1:]))
commands['/bin/bash'] = command_sh
commands['/bin/sh'] = command_sh


class command_chmod(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        if len(self.args) < 2:
            self.writeln('chmod: missing operand')
            self.writeln('Try chmod --help for more information.')
            return
        for arg in self.args[1:]:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if not self.fs.exists(path):
                self.writeln(
                    'chmod: cannot access %s: No such file or directory' % \
                    (arg,))
commands['/bin/chmod'] = command_chmod



class command_perl(HoneyPotCommand):
    """
    """
    def start(self):
        """
        """
        if not len(self.args):
            pass
        elif self.args[0] == '-v':
            output = (
                '',
                'This is perl 5, version 14, subversion 2 (v5.14.2) built for x86_64-linux-thread-multi',
                '',
                'Copyright 1987-2014, Larry Wall',
                '',
                'Perl may be copied only under the terms of either the Artistic License or the',
                'GNU General Public License, which may be found in the Perl 5 source kit.',
                '',
                'Complete documentation for Perl, including FAQ lists, should be found on',
                'this system using "man perl" or "perldoc perl".  If you have access to the',
                'Internet, point your browser at http://www.perl.org/, the Perl Home Page.',
                ''
            )
            for l in output:
                self.writeln(l)
            self.exit()
        elif self.args[0] == '-h':
            output = (
                '',
                'Usage: perl [switches] [--] [programfile] [arguments]',
                '  -0[octal]         specify record separator (\0, if no argument)',
                '  -a                autosplit mode with -n or -p (splits $_ into @F)',
                '  -C[number/list]   enables the listed Unicode features',
                '  -c                check syntax only (runs BEGIN and CHECK blocks)',
                '  -d[:debugger]     run program under debugger',
                '  -D[number/list]   set debugging flags (argument is a bit mask or alphabets)',
                "  -e program        one line of program (several -e's allowed, omit programfile)",
                '  -E program        like -e, but enables all optional features',
                "  -f                don't do $sitelib/sitecustomize.pl at startup",
                "  -F/pattern/       split() pattern for -a switch (//'s are optional)",
                '  -i[extension]     edit <> files in place (makes backup if extension supplied)',
                "  -Idirectory       specify @INC/#include directory (several -I's allowed)",
                '  -l[octal]         enable line ending processing, specifies line terminator',
                '  -[mM][-]module    execute "use/no module..." before executing program',
                '  -n                assume "while (<>) { ... }" loop around program',
                '  -p                assume loop like -n but print line also, like sed',
                '  -s                enable rudimentary parsing for switches after programfile',
                '  -S                look for programfile using PATH environment variable',
                '  -t                enable tainting warnings',
                '  -T                enable tainting checks',
                '  -u                dump core after parsing program',
                '  -U                allow unsafe operations',
                '  -v                print version, subversion (includes VERY IMPORTANT perl info)',
                '  -V[:variable]     print configuration summary (or a single Config.pm variable)',
                '  -w                enable many useful warnings (RECOMMENDED)',
                '  -W                enable all warnings',
                '  -x[directory]     strip off text before #!perl line and perhaps cd to directory',
                '  -X                disable all warnings',
                ''
            )
            for l in output:
                self.writeln(l)
            self.exit()
        else:
            self.exit()


    def lineReceived(self, line):
        """
        """
        log.msg( eventid='KIPP0008', realm='perl', input=line,
            format='INPUT (%(realm)s): %(input)s' )


    def handle_CTRL_D(self):
        """
        """
        self.exit()

commands['/usr/bin/perl'] = command_perl



class command_php(HoneyPotCommand):
    """
    """
    def start(self):
        """
        """
        if not len(self.args):
            pass
        elif self.args[0] == '-v':
            output = (
                'PHP 5.3.5 (cli)',
                'Copyright (c) 1997-2010 The PHP Group'
            )
            for l in output:
                self.writeln(l)
            self.exit()
        elif self.args[0] == '-h':
            output = (
                'Usage: php [options] [-f] <file> [--] [args...]',
                '       php [options] -r <code> [--] [args...]',
                '       php [options] [-B <begin_code>] -R <code> [-E <end_code>] [--] [args...]',
                '       php [options] [-B <begin_code>] -F <file> [-E <end_code>] [--] [args...]',
                '       php [options] -- [args...]',
                '       php [options] -a',
                '',
                '  -a               Run interactively',
                '  -c <path>|<file> Look for php.ini file in this directory',
                '  -n               No php.ini file will be used',
                "  -d foo[=bar]     Define INI entry foo with value 'bar'",
                '  -e               Generate extended information for debugger/profiler',
                '  -f <file>        Parse and execute <file>.',
                '  -h               This help',
                '  -i               PHP information',
                '  -l               Syntax check only (lint)',
                '  -m               Show compiled in modules',
                '  -r <code>        Run PHP <code> without using script tags <?..?>',
                '  -B <begin_code>  Run PHP <begin_code> before processing input lines',
                '  -R <code>        Run PHP <code> for every input line',
                '  -F <file>        Parse and execute <file> for every input line',
                '  -E <end_code>    Run PHP <end_code> after processing all input lines',
                '  -H               Hide any passed arguments from external tools.',
                '  -s               Output HTML syntax highlighted source.',
                '  -v               Version number',
                '  -w               Output source with stripped comments and whitespace.',
                '  -z <file>        Load Zend extension <file>.',
                '',
                '  args...          Arguments passed to script. Use -- args when first argument',
                '                   starts with - or script is read from stdin',
                '',
                '  --ini            Show configuration file names',
                '',
                '  --rf <name>      Show information about function <name>.',
                '  --rc <name>      Show information about class <name>.',
                '  --re <name>      Show information about extension <name>.',
                '  --ri <name>      Show configuration for extension <name>.',
                ''
            )
            for l in output:
                self.writeln(l)
            self.exit()
        else:
            self.exit()


    def lineReceived(self, line):
        """
        """
        log.msg( eventid='KIPP0008', realm='php', input=line,
            format='INPUT (%(realm)s): %(input)s' )


    def handle_CTRL_D(self):
        """
        """
        self.exit()

commands['/usr/bin/php'] = command_php



class command_chattr(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        if len(self.args) < 1:
            self.writeln('Usage: chattr [-RVf] [-+=AacDdeijsSu] [-v version] files...')
            return
        elif len(self.args) < 2:
            self.writeln("Must use '-v', =, - or +'")
            return
        if not self.fs.exists(self.args[1]):
            self.writeln('chattr: No such file or directory while trying to stat ' + self.args[1])
        return
commands['/usr/bin/chattr'] = command_chattr



class command_nop(HoneyPotCommand):
    """
    """
    def call(self):
        """
        """
        pass
commands['umask'] = command_nop
commands['set'] = command_nop
commands['unset'] = command_nop
commands['export'] = command_nop
commands['alias'] = command_nop
commands['jobs'] = command_nop
commands['/bin/kill'] = command_nop
commands['/bin/killall'] = command_nop
commands['/bin/killall5'] = command_nop
commands['/bin/su'] = command_nop
commands['/bin/chown'] = command_nop
commands['/bin/chgrp'] = command_nop
commands['/usr/bin/chattr'] = command_nop

# vim: set sw=4 et:
