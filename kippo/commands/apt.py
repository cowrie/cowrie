# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from twisted.internet import reactor, defer
from twisted.internet.defer import inlineCallbacks
from kippo.core.honeypot import HoneyPotCommand
import random, re

commands = {}

class command_faked_package_class_factory(object):
    @staticmethod
    def getCommand(name):
        class command_faked_installation(HoneyPotCommand):
            def call(self):
                self.writeln("%s: Segmentation fault" % name)
        return command_faked_installation

'''apt-get fake
suppports only the 'install PACKAGE' command & 'moo'.
Any installed packages, places a 'Segfault' at /usr/bin/PACKAGE.'''
class command_aptget(HoneyPotCommand):
    def start(self):
        if len(self.args) > 0 and self.args[0] == 'install':
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

    @inlineCallbacks
    def do_install(self,*args):
        if len(self.args) <= 1:
            self.writeln('0 upgraded, 0 newly installed, 0 to remove and %s not upgraded.' % random.randint(200,300))
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

        self.writeln('Reading package lists... Done')
        self.writeln('Building dependency tree')
        self.writeln('Reading state information... Done')
        self.writeln('The following NEW packages will be installed:')
        self.writeln('  %s ' % ' '.join(packages))
        self.writeln('0 upgraded, %d newly installed, 0 to remove and 259 not upgraded.' % \
            len(packages))
        self.writeln('Need to get %s.2kB of archives.' % (totalsize))
        self.writeln('After this operation, %skB of additional disk space will be used.' % \
            (totalsize * 2.2,))
        i = 1
        for p in packages:
            self.writeln('Get:%d http://ftp.debian.org stable/main %s %s [%s.2kB]' % \
                (i, p, packages[p]['version'], packages[p]['size']))
            i += 1
            yield self.sleep(1, 2)
        self.writeln('Fetched %s.2kB in 1s (4493B/s)''' % (totalsize))
        self.writeln('Reading package fields... Done')
        yield self.sleep(1, 2)
        self.writeln('Reading package status... Done')
        self.writeln('(Reading database ... 177887 files and directories currently installed.)')
        yield self.sleep(1, 2)
        for p in packages:
            self.writeln('Unpacking %s (from .../archives/%s_%s_i386.deb) ...' % \
                (p, p, packages[p]['version']))
            yield self.sleep(1, 2)
        self.writeln('Processing triggers for man-db ...')
        yield self.sleep(2)
        for p in packages:
            self.writeln('Setting up %s (%s) ...' % \
                (p, packages[p]['version']))
            self.fs.mkfile('/usr/bin/%s' % p,
                0, 0, random.randint(10000, 90000), 33188)
            self.honeypot.commands['/usr/bin/%s' % p] = \
                command_faked_package_class_factory.getCommand(p)
            yield self.sleep(2)
        self.exit()

    def do_moo(self):
        self.writeln('         (__)')
        self.writeln('         (oo)')
        self.writeln('   /------\/')
        self.writeln('  / |    ||')
        self.writeln(' *  /\---/\ ')
        self.writeln('    ~~   ~~')
        self.writeln('...."Have you mooed today?"...')
        self.exit()

    def do_locked(self):
        self.writeln('E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)')
        self.writeln('E: Unable to lock the list directory')
        self.exit()
commands['/usr/bin/apt-get'] = command_aptget

# vim: set sw=4 et tw=0:
