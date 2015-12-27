# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import random
import re

from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_faked_package_class_factory(object):
    @staticmethod
    def getCommand(name):
        class command_faked_installation(HoneyPotCommand):
            def call(self):
                self.write("%s: Segmentation fault\n" % name)
        return command_faked_installation

class command_aptget(HoneyPotCommand):
    """
    apt-get fake
    suppports only the 'install PACKAGE' command & 'moo'.
    Any installed packages, places a 'Segfault' at /usr/bin/PACKAGE.'''
    """
    def start(self):
        if len(self.args) == 0:
            self.do_help()
        elif len(self.args) > 0 and self.args[0] == '-v':
            self.do_version()
        elif len(self.args) > 0 and self.args[0] == 'install':
            self.do_install()
        elif len(self.args) > 0 and self.args[0] == 'moo':
            self.do_moo()
        else:
            self.do_locked()

    def sleep(self, time, time2 = None):
        d = defer.Deferred()
        if time2:
            time = random.randint(time * 100, time2 * 100) / 100.0
        reactor.callLater(time, d.callback, None)
        return d

    def do_version(self):
        self.write('''apt 1.0.9.8.1 for amd64 compiled on Jun 10 2015 09:42:06
Supported modules:
*Ver: Standard .deb
*Pkg:  Debian dpkg interface (Priority 30)
 Pkg:  Debian APT solver interface (Priority -1000)
 S.L: 'deb' Standard Debian binary tree
 S.L: 'deb-src' Standard Debian source tree
 Idx: Debian Source Index
 Idx: Debian Package Index
 Idx: Debian Translation Index
 Idx: Debian dpkg status file
 Idx: EDSP scenario file\n''')
        self.exit()
        return

    def do_help(self):
        self.write('''apt 1.0.9.8.1 for amd64 compiled on Jun 10 2015 09:42:06
Usage: apt-get [options] command
       apt-get [options] install|remove pkg1 [pkg2 ...]
       apt-get [options] source pkg1 [pkg2 ...]

apt-get is a simple command line interface for downloading and
installing packages. The most frequently used commands are update
and install.

Commands:
   update - Retrieve new lists of packages
   upgrade - Perform an upgrade
   install - Install new packages (pkg is libc6 not libc6.deb)
   remove - Remove packages
   autoremove - Remove automatically all unused packages
   purge - Remove packages and config files
   source - Download source archives
   build-dep - Configure build-dependencies for source packages
   dist-upgrade - Distribution upgrade, see apt-get(8)
   dselect-upgrade - Follow dselect selections
   clean - Erase downloaded archive files
   autoclean - Erase old downloaded archive files
   check - Verify that there are no broken dependencies
   changelog - Download and display the changelog for the given package
   download - Download the binary package into the current directory

Options:
  -h  This help text.
  -q  Loggable output - no progress indicator
  -qq No output except for errors
  -d  Download only - do NOT install or unpack archives
  -s  No-act. Perform ordering simulation
  -y  Assume Yes to all queries and do not prompt
  -f  Attempt to correct a system with broken dependencies in place
  -m  Attempt to continue if archives are unlocatable
  -u  Show a list of upgraded packages as well
  -b  Build the source package after fetching it
  -V  Show verbose version numbers
  -c=? Read this configuration file
  -o=? Set an arbitrary configuration option, eg -o dir::cache=/tmp
See the apt-get(8), sources.list(5) and apt.conf(5) manual
pages for more information and options.
                       This APT has Super Cow Powers.\n''')
        self.exit()
        return

    @inlineCallbacks
    def do_install(self,*args):
        if len(self.args) <= 1:
            self.write('0 upgraded, 0 newly installed, 0 to remove and %s not upgraded.\n' % random.randint(200,300))
            self.exit()
            return

        packages = {}
        for y in [re.sub('[^A-Za-z0-9]', '', x) for x in self.args[1:]]:
            packages[y] = {
                'version':      '%d.%d-%d' % \
                    (random.choice((0, 1)),
                    random.randint(1, 40),
                    random.randint(1, 10)),
                'size':         random.randint(100, 900)
                }
        totalsize = sum([packages[x]['size'] for x in packages])

        self.write('Reading package lists... Done\n')
        self.write('Building dependency tree\n')
        self.write('Reading state information... Done\n')
        self.write('The following NEW packages will be installed:\n')
        self.write('  %s ' % ' '.join(packages) + '\n')
        self.write('0 upgraded, %d newly installed, 0 to remove and 259 not upgraded.\n' % \
            len(packages))
        self.write('Need to get %s.2kB of archives.\n' % (totalsize))
        self.write('After this operation, %skB of additional disk space will be used.\n' % \
            (totalsize * 2.2,))
        i = 1
        for p in packages:
            self.write('Get:%d http://ftp.debian.org stable/main %s %s [%s.2kB]\n' % \
                (i, p, packages[p]['version'], packages[p]['size']))
            i += 1
            yield self.sleep(1, 2)
        self.write('Fetched %s.2kB in 1s (4493B/s)''\n' % (totalsize))
        self.write('Reading package fields... Done\n')
        yield self.sleep(1, 2)
        self.write('Reading package status... Done\n')
        self.write('(Reading database ... 177887 files and directories currently installed.)\n')
        yield self.sleep(1, 2)
        for p in packages:
            self.write('Unpacking %s (from .../archives/%s_%s_i386.deb) ...\n' % \
                (p, p, packages[p]['version']))
            yield self.sleep(1, 2)
        self.write('Processing triggers for man-db ...\n')
        yield self.sleep(2)
        for p in packages:
            self.write('Setting up %s (%s) ...\n' % \
                (p, packages[p]['version']))
            self.fs.mkfile('/usr/bin/%s' % p,
                0, 0, random.randint(10000, 90000), 33188)
            self.protocol.commands['/usr/bin/%s' % p] = \
                command_faked_package_class_factory.getCommand(p)
            yield self.sleep(2)
        self.exit()

    def do_moo(self):
        self.write('         (__)\n')
        self.write('         (oo)\n')
        self.write('   /------\/\n')
        self.write('  / |    ||\n')
        self.write(' *  /\---/\ \n')
        self.write('    ~~   ~~\n')
        self.write('...."Have you mooed today?"...\n')
        self.exit()

    def do_locked(self):
        self.write('E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)\n')
        self.write('E: Unable to lock the list directory\n')
        self.exit()
commands['/usr/bin/apt-get'] = command_aptget

# vim: set sw=4 et tw=0:
