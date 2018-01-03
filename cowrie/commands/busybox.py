"""
"""

from __future__ import division, absolute_import

from cowrie.shell.honeypot import HoneyPotCommand,StdOutStdErrEmulationProtocol
from twisted.python import log
commands = {}

busybox_help=('''
BusyBox v1.20.2 (Debian 1:1.20.0-7) multi-call binary.
Copyright (C) 1998-2011 Erik Andersen, Rob Landley, Denys Vlasenko
and others. Licensed under GPLv2.
See source distribution for full notice.

Usage: busybox [function] [arguments]...
   or: busybox --list[-full]
   or: busybox --install [-s] [DIR]
   or: function [arguments]...

	BusyBox is a multi-call binary that combines many common Unix
	utilities into a single executable.  Most people will create a
	link to busybox for each function they wish to use and BusyBox
	will act like whatever it was invoked as.

Currently defined functions:
	[, [[, adjtimex, ar, arp, arping, ash, awk, basename, blockdev, brctl,
	bunzip2, bzcat, bzip2, cal, cat, chgrp, chmod, chown, chroot, chvt,
	clear, cmp, cp, cpio, cttyhack, cut, date, dc, dd, deallocvt, depmod,
	df, diff, dirname, dmesg, dnsdomainname, dos2unix, du, dumpkmap,
	dumpleases, echo, egrep, env, expand, expr, false, fgrep, find, fold,
	free, freeramdisk, ftpget, ftpput, getopt, getty, grep, groups, gunzip,
	gzip, halt, head, hexdump, hostid, hostname, httpd, hwclock, id,
	ifconfig, init, insmod, ionice, ip, ipcalc, kill, killall, klogd, last,
	less, ln, loadfont, loadkmap, logger, login, logname, logread, losetup,
	ls, lsmod, lzcat, lzma, md5sum, mdev, microcom, mkdir, mkfifo, mknod,
	mkswap, mktemp, modinfo, modprobe, more, mount, mt, mv, nameif, nc,
	netstat, nslookup, od, openvt, patch, pidof, ping, ping6, pivot_root,
	poweroff, printf, ps, pwd, rdate, readlink, realpath, reboot, renice,
	reset, rev, rm, rmdir, rmmod, route, rpm, rpm2cpio, run-parts, sed, seq,
	setkeycodes, setsid, sh, sha1sum, sha256sum, sha512sum, sleep, sort,
	start-stop-daemon, stat, strings, stty, swapoff, swapon, switch_root,
	sync, sysctl, syslogd, tac, tail, tar, taskset, tee, telnet, test, tftp,
	time, timeout, top, touch, tr, traceroute, traceroute6, true, tty,
	udhcpc, udhcpd, umount, uname, uncompress, unexpand, uniq, unix2dos,
	unlzma, unxz, unzip, uptime, usleep, uudecode, uuencode, vconfig, vi,
	watch, watchdog, wc, wget, which, who, whoami, xargs, xz, xzcat, yes,
	zcat
''').strip().split('\n')

class command_busybox(HoneyPotCommand):
    """
    """

    def help(self):
        """
        """
        for ln in busybox_help:
            self.errorWrite(ln+'\n')


    def call(self):
        """
        """
        if len(self.args) == 0:
            self.help()
            return

        line = ' '.join(self.args)
        cmd = self.args[0]
        cmdclass = self.protocol.getCommand(cmd,
                                            self.environ['PATH'].split(':'))
        if cmdclass:
            log.msg(eventid='cowrie.command.success',
                    input=line,
                    format='Command found: %(input)s')
            command = StdOutStdErrEmulationProtocol(self.protocol,cmdclass,self.args[1:],self.input_data,None)
            # Workaround for the issue: #352
            # https://github.com/fe7ch/cowrie/commit/9b33509
            # For an unknown reason inserted command won't be invoked later, if it's followed by an invalid command
            # so lets just call the command in question
            # self.protocol.pp.insert_command(command)
            self.protocol.call_command(command, cmdclass, *self.args[1:])

            # Place this here so it doesn't write out only if last statement

            if self.input_data:
                self.write(self.input_data)
        else:
            self.write('{}: applet not found\n'.format(cmd))

commands['busybox'] = command_busybox
commands['/bin/busybox'] = command_busybox
