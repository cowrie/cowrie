# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import os
import shlex
import re
import copy

from twisted.python import log

from cowrie.core import fs

class HoneyPotCommand(object):
    """
    """

    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = args
        self.environ = self.protocol.cmdstack[0].environ
        self.writeln = self.protocol.writeln
        self.write = self.protocol.terminal.write
        self.nextLine = self.protocol.terminal.nextLine
        self.fs = self.protocol.fs


    def start(self):
        """
        """
        self.call()
        self.exit()


    def call(self):
        """
        """
        self.writeln('Hello World! [%s]' % (repr(self.args),))


    def exit(self):
        """
        """
        self.protocol.cmdstack.pop()
        self.protocol.cmdstack[-1].resume()


    def handle_CTRL_C(self):
        """
        """
        log.msg('Received CTRL-C, exiting..')
        self.writeln('^C')
        self.exit()


    def lineReceived(self, line):
        """
        """
        log.msg('QUEUED INPUT: %s' % (line,))
        # FIXME: naive command parsing, see lineReceived below
        self.protocol.cmdstack[0].cmdpending.append(line)


    def resume(self):
        """
        """
        pass


    def handle_TAB(self):
        """
        """
        pass


    def handle_CTRL_D(self):
        """
        """
        pass



class HoneyPotShell(object):
    """
    """

    def __init__(self, protocol, interactive=True):
        self.protocol = protocol
        self.interactive = interactive
        self.showPrompt()
        self.cmdpending = []
        self.environ = protocol.environ


    def lineReceived(self, line):
        """
        """
        log.msg('CMD: %s' % (line,))
        line = line[:500]
        comment = re.compile('^\s*#')
        for i in [x.strip() for x in re.split(';|&&|\n', line.strip())[:10]]:
            if not len(i):
                continue
            if comment.match(i):
                continue
            self.cmdpending.append(i)
        if len(self.cmdpending):
            self.runCommand()
        else:
            self.showPrompt()


    def runCommand(self):
        """
        """
        def runOrPrompt():
            if len(self.cmdpending):
                self.runCommand()
            elif self.interactive:
                self.showPrompt()
            else:
                self.protocol.terminal.transport.session.loseConnection()

        if not len(self.cmdpending):
            if self.interactive:
                self.showPrompt()
            else:
                self.protocol.terminal.transport.session.loseConnection()
            return

        line = self.cmdpending.pop(0)
        try:
            line = line.replace('>', ' > ').replace('|', ' | ').replace('<',' < ')
            cmdAndArgs = shlex.split(line)
        except:
            self.protocol.writeln(
                'bash: syntax error: unexpected end of file')
            # Could run runCommand here, but i'll just clear the list instead
            self.cmdpending = []
            self.showPrompt()
            return

        # Probably no reason to be this comprehensive for just PATH...
        environ = copy.copy(self.environ)
        cmd = None
        while len(cmdAndArgs):
            piece = cmdAndArgs.pop(0)
            if piece.count('='):
                key, value = piece.split('=', 1)
                environ[key] = value
                continue
            cmd = piece
            break
        args = cmdAndArgs

        if not cmd:
            runOrPrompt()
            return

        rargs = []
        for arg in args:
            matches = self.protocol.fs.resolve_path_wc(arg, self.protocol.cwd)
            if matches:
                rargs.extend(matches)
            else:
                rargs.append(arg)
        cmdclass = self.protocol.getCommand(cmd, environ['PATH'].split(':'))
        if cmdclass:
            log.msg(eventid='KIPP0005', input=line, format='Command found: %(input)s')
            self.protocol.call_command(cmdclass, *rargs)
        else:
            log.msg(eventid='KIPP0006',
                input=line, format='Command not found: %(input)s')
            if len(line):
                self.protocol.writeln('bash: %s: command not found' % (cmd,))
                runOrPrompt()


    def resume(self):
        """
        """
        if self.interactive:
            self.protocol.setInsertMode()
        self.runCommand()


    def showPrompt(self):
        """
        """
        if not self.interactive:
            return
        # Example: srv03:~#
        #prompt = '%s:%%(path)s' % self.protocol.hostname
        # Example: root@svr03:~#     (More of a "Debianu" feel)
        prompt = '%s@%s:%%(path)s' % (self.protocol.user.username, self.protocol.hostname,)
        # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
        #prompt = '[%s@%s %%(path)s]' % (self.protocol.user.username, self.protocol.hostname,)
        if not self.protocol.user.uid:
            prompt += '# '    # "Root" user
        else:
            prompt += '$ '    # "Non-Root" user

        path = self.protocol.cwd
        homelen = len(self.protocol.user.avatar.home)
        if path == self.protocol.user.avatar.home:
            path = '~'
        elif len(path) > (homelen+1) and \
                path[:(homelen+1)] == self.protocol.user.avatar.home + '/':
            path = '~' + path[homelen:]
        # Uncomment the three lines below for a 'better' CentOS look.
        # Rather than '[root@svr03 /var/log]#' is shows '[root@svr03 log]#'.
        #path = path.rsplit('/', 1)[-1]
        #if not path:
        #    path = '/'

        attrs = {'path': path}
        self.protocol.terminal.write(prompt % attrs)


    def handle_CTRL_C(self):
        """
        """
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.nextLine()
        self.showPrompt()


    def handle_CTRL_D(self):
        """
        """
        log.msg('Received CTRL-D, exiting..')
        self.protocol.call_command(self.protocol.commands['exit'])


    def handle_TAB(self):
        """
        """
        if not len(self.protocol.lineBuffer):
            return
        l = ''.join(self.protocol.lineBuffer)
        if l[-1] == ' ':
            clue = ''
        else:
            clue = ''.join(self.protocol.lineBuffer).split()[-1]
        try:
            basedir = os.path.dirname(clue)
        except:
            pass
        if len(basedir) and basedir[-1] != '/':
            basedir += '/'

        files = []
        tmppath = basedir
        if not len(basedir):
            tmppath = self.protocol.cwd
        try:
            r = self.protocol.fs.resolve_path(tmppath, self.protocol.cwd)
        except:
            return
        for x in self.protocol.fs.get_path(r):
            if clue == '':
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if len(files) == 0:
            return

        # Clear early so we can call showPrompt if needed
        for i in range(self.protocol.lineBufferIndex):
            self.protocol.terminal.cursorBackward()
            self.protocol.terminal.deleteCharacter()

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
            if newbuf == ''.join(self.protocol.lineBuffer):
                self.protocol.terminal.nextLine()
                maxlen = max([len(x[fs.A_NAME]) for x in files]) + 1
                perline = int(self.protocol.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.protocol.terminal.nextLine()
                    self.protocol.terminal.write(file[fs.A_NAME].ljust(maxlen))
                    count += 1
                self.protocol.terminal.nextLine()
                self.showPrompt()

        self.protocol.lineBuffer = list(newbuf)
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbuf)

