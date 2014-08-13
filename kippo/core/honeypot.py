# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import twisted
from copy import deepcopy, copy
import os
import shlex

from kippo.core import fs
from kippo.core.config import config
import kippo.core.exceptions
from kippo import core

import pickle

class HoneyPotCommand(object):
    def __init__(self, honeypot, *args):
        self.honeypot = honeypot
        self.args = args
        self.writeln = self.honeypot.writeln
        self.write = self.honeypot.terminal.write
        self.nextLine = self.honeypot.terminal.nextLine
        self.fs = self.honeypot.fs

    def start(self):
        self.call()
        self.exit()

    def call(self):
        self.honeypot.writeln('Hello World! [%s]' % repr(self.args))

    def exit(self):
        self.honeypot.cmdstack.pop()
        self.honeypot.cmdstack[-1].resume()

    def ctrl_c(self):
        print 'Received CTRL-C, exiting..'
        self.writeln('^C')
        self.exit()

    def lineReceived(self, line):
        print 'INPUT: %s' % line

    def resume(self):
        pass

    def handle_TAB(self):
        pass

class HoneyPotShell(object):
    def __init__(self, honeypot, interactive = True):
        self.honeypot = honeypot
        self.interactive = interactive
        self.showPrompt()
        self.cmdpending = []
        self.envvars = {
            'PATH':     '/bin:/usr/bin:/sbin:/usr/sbin',
            }

    def lineReceived(self, line):
        print 'CMD: %s' % line
        line = line[:500]
        for i in [x.strip() for x in line.strip().split(';')[:10]]:
            if not len(i):
                continue
            self.cmdpending.append(i)
        if len(self.cmdpending):
            self.runCommand()
        else:
            self.showPrompt()

    def runCommand(self):
        def runOrPrompt():
            if len(self.cmdpending):
                self.runCommand()
            else:
                self.showPrompt()

        if not len(self.cmdpending):
            if self.interactive:
                self.showPrompt()
            else:
                self.honeypot.terminal.transport.loseConnection()
            return

        line = self.cmdpending.pop(0)
        try:
            cmdAndArgs = shlex.split(line)
        except:
            self.honeypot.writeln(
                'bash: syntax error: unexpected end of file')
            # could run runCommand here, but i'll just clear the list instead
            self.cmdpending = []
            self.showPrompt()
            return

        # probably no reason to be this comprehensive for just PATH...
        envvars = copy(self.envvars)
        cmd = None
        while len(cmdAndArgs):
            piece = cmdAndArgs.pop(0)
            if piece.count('='):
                key, value = piece.split('=', 1)
                envvars[key] = value
                continue
            cmd = piece
            break
        args = cmdAndArgs

        if not cmd:
            runOrPrompt()
            return

        rargs = []
        for arg in args:
            matches = self.honeypot.fs.resolve_path_wc(arg, self.honeypot.cwd)
            if matches:
                rargs.extend(matches)
            else:
                rargs.append(arg)
        cmdclass = self.honeypot.getCommand(cmd, envvars['PATH'].split(':'))
        if cmdclass:
            print 'Command found: %s' % (line,)
            self.honeypot.logDispatch('Command found: %s' % (line,))
            self.honeypot.call_command(cmdclass, *rargs)
        else:
            self.honeypot.logDispatch('Command not found: %s' % (line,))
            print 'Command not found: %s' % (line,)
            if len(line):
                self.honeypot.writeln('bash: %s: command not found' % cmd)
                runOrPrompt()

    def resume(self):
        if self.interactive:
            self.honeypot.setInsertMode()
        self.runCommand()

    def showPrompt(self):
        if not self.interactive:
            return
        # Example: srv03:~#
        #prompt = '%s:%%(path)s' % self.honeypot.hostname
        # Example: root@svr03:~#     (More of a "Debianu" feel)
        prompt = '%s@%s:%%(path)s' % (self.honeypot.user.username, self.honeypot.hostname,)
        # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
        #prompt = '[%s@%s %%(path)s]' % (self.honeypot.user.username, self.honeypot.hostname,)
        if not self.honeypot.user.uid:
            prompt += '# '    # "Root" user
        else:
            prompt += '$ '    # "Non-Root" user

        path = self.honeypot.cwd
        homelen = len(self.honeypot.user.home)
        if path == self.honeypot.user.home:
            path = '~'
        elif len(path) > (homelen+1) and \
                path[:(homelen+1)] == self.honeypot.user.home + '/':
            path = '~' + path[homelen:]
        # Uncomment the three lines below for a 'better' CenOS look.
        # Rather than '[root@svr03 /var/log]#' is shows '[root@svr03 log]#'.
        #path = path.rsplit('/', 1)[-1]
        #if not path:
        #    path = '/'

        attrs = {'path': path}
        self.honeypot.terminal.write(prompt % attrs)

    def ctrl_c(self):
        self.honeypot.lineBuffer = []
        self.honeypot.lineBufferIndex = 0
        self.honeypot.terminal.nextLine()
        self.showPrompt()

    # Tab completion
    def handle_TAB(self):
        if not len(self.honeypot.lineBuffer):
            return
        l = ''.join(self.honeypot.lineBuffer)
        if l[-1] == ' ':
            clue = ''
        else:
            clue = ''.join(self.honeypot.lineBuffer).split()[-1]
        try:
            basedir = os.path.dirname(clue)
        except:
            pass
        if len(basedir) and basedir[-1] != '/':
            basedir += '/'

        files = []
        tmppath = basedir
        if not len(basedir):
            tmppath = self.honeypot.cwd
        try:
            r = self.honeypot.fs.resolve_path(tmppath, self.honeypot.cwd)
        except:
            return
        for x in self.honeypot.fs.get_path(r):
            if clue == '':
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if len(files) == 0:
            return

        # Clear early so we can call showPrompt if needed
        for i in range(self.honeypot.lineBufferIndex):
            self.honeypot.terminal.cursorBackward()
            self.honeypot.terminal.deleteCharacter()

        newbuf = ''
        if len(files) == 1:
            newbuf = ' '.join(l.split()[:-1] + \
                ['%s%s' % (basedir, files[0][fs.A_NAME])])
            if files[0][fs.A_TYPE] == fs.T_DIR:
                newbuf += '/'
            else:
                newbuf += ' '
        else:
            if len(os.path.basename(clue)):
                prefix = os.path.commonprefix([x[fs.A_NAME] for x in files])
            else:
                prefix = ''
            first = l.split(' ')[:-1]
            newbuf = ' '.join(first + ['%s%s' % (basedir, prefix)])
            if newbuf == ''.join(self.honeypot.lineBuffer):
                self.honeypot.terminal.nextLine()
                maxlen = max([len(x[fs.A_NAME]) for x in files]) + 1
                perline = int(self.honeypot.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.honeypot.terminal.nextLine()
                    self.honeypot.terminal.write(file[fs.A_NAME].ljust(maxlen))
                    count += 1
                self.honeypot.terminal.nextLine()
                self.showPrompt()

        self.honeypot.lineBuffer = list(newbuf)
        self.honeypot.lineBufferIndex = len(self.honeypot.lineBuffer)
        self.honeypot.terminal.write(newbuf)

class HoneyPotEnvironment(object):
    def __init__(self):
        self.cfg = config()
        self.commands = {}
        import kippo.commands
        for c in kippo.commands.__all__:
            module = __import__('kippo.commands.%s' % c,
                globals(), locals(), ['commands'])
            self.commands.update(module.commands)
        self.fs = pickle.load(file(
            self.cfg.get('honeypot', 'filesystem_file'), 'rb'))

# vim: set sw=4 et:
