# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from zope.interface import implementer

import os
import re
import stat
import copy
import time

from twisted.python import log, failure
from twisted.internet import error

from twisted.internet.interfaces import IProcessProtocol

from cowrie.core import fs
from cowrie.core import shlex


class HoneyPotCommand(object):
    """
    """
    def __init__(self, stdout, protocol, *args):
        self.protocol = protocol
        self.args = list(args)
        self.environ = self.protocol.cmdstack[0].environ
        self.fs = self.protocol.fs
        self.data = None
        self.input_data = None
        self.process_type = "nonePipe"

        self.write = stdout.outReceived
        self.errorWrite = stdout.errReceived
        # MS-DOS style redirect handling, inside the command
        # TODO: handle >>, 2>, etc
        if '>' in self.args:
            self.writtenBytes = 0
            self.write = self.write_to_file
            index = self.args.index(">")
            self.outfile = self.fs.resolve_path(str(self.args[(index + 1)]), self.protocol.cwd)
            del self.args[index:]
            self.safeoutfile = '%s/%s-%s-%s-redir_%s' % (
                self.protocol.cfg.get('honeypot', 'download_path'),
                time.strftime('%Y%m%d-%H%M%S'),
                self.protocol.getProtoTransport().transportId,
                self.protocol.terminal.transport.session.id,
                re.sub('[^A-Za-z0-9]', '_', self.outfile))
            perm = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            self.fs.mkfile(self.outfile, 0, 0, 0, stat.S_IFREG | perm)
            with open(self.safeoutfile, 'a'):
                self.fs.update_realfile(self.fs.getfile(self.outfile), self.safeoutfile)


    def check_arguments(self, application, args):
        """
        """
        files = []
        for arg in args:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if self.fs.isdir(path):
                self.errorWrite("{}: error reading `{}': Is a directory\n".format(application, arg))
                continue
            files.append(path)
        return files


    def set_input_data(self, data):
        """
        """
        self.input_data = data


    def set_process_type(self, data):
        """
        """
        self.process_type = data


    def write_to_file(self, data):
        """
        Support '>' to write to a file
        """
        with open(self.safeoutfile, 'a') as f:
            f.write(data)
        self.writtenBytes += len(data)
        self.fs.update_size(self.outfile, self.writtenBytes)


    def start(self):
        """
        """
        self.call()
        self.exit()


    def call(self):
        """
        """
        self.write('Hello World! [%s]\n' % (repr(self.args),))


    def exit(self):
        """
        Sometimes client is disconnected and command exits after. So cmdstack is gone
        """
        try:

            self.protocol.pp.removeFromStack()
            """
            If Cmd Stack is equal to 1 means its the base shell
            """
            if (len(self.protocol.cmdstack) == 1):
                self.protocol.cmdstack[-1].showPrompt()

        except Exception as inst:
            log.msg("Exception: " + str(inst))
            log.msg("Command Stack: " + str(self.protocol.cmdstack))
            # ignore disregarded stack requests
            # Cmdstack could be gone already (wget + disconnect)
            pass


    def handle_CTRL_C(self):
        """
        """
        log.msg('Received CTRL-C, exiting..')
        self.write('^C\n')
        self.exit()


    def lineReceived(self, line):
        """
        """
        log.msg('QUEUED INPUT: {}'.format(line))
        # FIXME: naive command parsing, see lineReceived below
        self.protocol.cmdstack[0].cmdpending.append(shlex.split(line))


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


    def __repr__(self):
        return str(self.__class__.__name__)



class HoneyPotShell(object):
    """
    """

    def __init__(self, protocol, interactive=True):
        self.protocol = protocol
        self.interactive = interactive
        self.cmdpending = []
        self.environ = protocol.environ
        self.lexer = None
        self.showPrompt()


    def lineReceived(self, line):
        """
        This tokenizes the received lines and handles environment variable substitution
        """
        log.msg(eventid='cowrie.command.input', input=line, format='CMD: %(input)s')
        self.lexer = shlex.shlex(instream=line, punctuation_chars=True)
        tokens = []
        while True:
            try:
                tok = self.lexer.get_token()
                # log.msg( "tok: %s" % (repr(tok)) )

                # end of the line
                if tok == self.lexer.eof:
                    if len(tokens):
                        cmd = {}
                        cmd['type'] = 'eof'
                        cmd['tokens'] = tokens
                        self.cmdpending.append(cmd)
                        tokens = []
                    break

                # For now, execute all after && and || until we have return codes
                elif tok == ';' or tok == '&&' or tok == '||':
                    if len(tokens):
                        cmd = {}
                        cmd['type'] = 'nonePipe'
                        cmd['tokens'] = tokens
                        self.cmdpending.append(cmd)
                        tokens = []
                        continue
                elif tok == '|':
                    if len(tokens):
                        cmd = {}
                        cmd['type'] = 'pipe'
                        cmd['tokens'] = tokens
                        self.cmdpending.append(cmd)
                        tokens = []
                        continue
                    else:
                        self.protocol.terminal.write(
                            '-bash: syntax error near unexpected token `{}\'\n'.format(tok))
                        break
                elif tok == '$?':
                    tok = "0"
                elif tok[0] == '$':
                    envRex = re.compile(r'^\$([_a-zA-Z0-9]+)$')
                    envSearch = envRex.search(tok)
                    if envSearch != None:
                        envMatch = envSearch.group(1)
                        if envMatch in list(self.environ.keys()):
                            tok = self.environ[envMatch]
                        else:
                            continue
                    envRex = re.compile(r'^\${([_a-zA-Z0-9]+)}$')
                    envSearch = envRex.search(tok)
                    if envSearch != None:
                        envMatch = envSearch.group(1)
                        if envMatch in list(self.environ.keys()):
                            tok = self.environ[envMatch]
                        else:
                            continue
                tokens.append(tok)
            except Exception as e:
                self.protocol.terminal.write(
                    'bash: syntax error: unexpected end of file\n')
                # Could run runCommand here, but i'll just clear the list instead
                log.msg("exception: {}".format(e))
                self.cmdpending = []
                return
        if len(self.cmdpending):
            self.runCommand()
        else:
            self.showPrompt()


    def runCommand(self):
        """
        """

        def parse_file_arguments(arguments):
            parsed_arguments = []
            for arg in arguments:
                matches = self.protocol.fs.resolve_path_wc(arg, self.protocol.cwd)
                if matches:
                    parsed_arguments.extend(matches)
                else:
                    parsed_arguments.append(arg)

            return parsed_arguments

        # this bit handles things like "PATH=/bin ls"
        environ = copy.copy(self.environ)
        cmd_array = []
        while len(self.cmdpending):
            cmd = self.cmdpending.pop(0)
            cmd['argv'] = []
            for i in cmd['tokens']:
                if i.count('='):
                    key, value = i.split('=', 1)
                    environ[key] = value
                    continue
                cmd['argv'].append(i)
            cmd_array.append(cmd)
            continue

        lastpp = None
        pp = None
        for index, cmd in reversed(list(enumerate(cmd_array))):
            if len(cmd['argv'])==0:
                continue
            cmdclass = self.protocol.getCommand(cmd['argv'][0], environ['PATH'].split(':'))
            if cmdclass:
                log.msg(eventid='cowrie.command.success',
                        input=" ".join(cmd['argv']),
                        format='Command found: %(input)s')
                if index == len(cmd_array) - 1:
                    lastpp = CowrieProcess(self.protocol, cmdclass, cmd, None, env=environ)
                    lastpp.addToStack()
                    pp = lastpp
                else:
                    pp = CowrieProcess(self.protocol, cmdclass, cmd, lastpp, env=environ)
                    pp.addToStack()
                    lastpp = pp
            else:
                log.msg(eventid='cowrie.command.failed',
                        input=" ".join(cmd['argv']),
                        format='Command not found: %(input)s')
                self.protocol.terminal.write('bash: %s: command not found\n' % (cmd['argv'][0],))
                self.showPrompt()
                return
        if pp:
            cmdclass = self.protocol.getCommand(cmd_array[0]['argv'][0], environ['PATH'].split(':'))
            pp.set_protocol(self.protocol)
            self.protocol.call_command(pp, cmdclass, *cmd_array[0]['argv'][1:])
        else:
            self.showPrompt()
            return


    def showPrompt(self):
        """
        """
        if not self.interactive:
            return
        # Example: srv03:~#
        #prompt = '%s:%%(path)s' % self.protocol.hostname
        # Example: root@svr03:~#     (More of a "Debianu" feel)
        prompt = '%s@%s:%%(path)s' % (self.protocol.user.username, self.protocol.hostname)
        # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
        #prompt = '[%s@%s %%(path)s]' % (self.protocol.user.username, self.protocol.hostname,)
        if not self.protocol.user.uid:
            prompt += '# '    # "Root" user
        else:
            prompt += '$ '    # "Non-Root" user

        cwd = self.protocol.cwd
        homelen = len(self.protocol.user.avatar.home)
        if cwd == self.protocol.user.avatar.home:
            cwd = '~'
        elif len(cwd) > (homelen+1) and \
                cwd[:(homelen+1)] == self.protocol.user.avatar.home + '/':
            cwd = '~' + cwd[homelen:]
        # Uncomment the three lines below for a 'better' CentOS look.
        # Rather than '[root@svr03 /var/log]#' is shows '[root@svr03 log]#'.
        #cwd = cwd.rsplit('/', 1)[-1]
        #if not cwd:
        #    cwd = '/'

        # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
        # Example: root@svr03:~#     (More of a "Debian" feel)
        prompt = '{}@{}:{}'.format(self.protocol.user.username, self.protocol.hostname, cwd)
        if not self.protocol.user.uid:
            prompt += '# '    # "Root" user
        else:
            prompt += '$ '    # "Non-Root" user
        self.protocol.terminal.write(prompt)
        self.protocol.ps = (prompt , '> ')


    def eofReceived(self):
        """
        this should probably not go through ctrl-d, but use processprotocol to close stdin
        """
        log.msg("received eof, sending ctrl-d to command")
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_D()


    def handle_CTRL_C(self):
        """
        """
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.write('\n')
        self.showPrompt()


    def handle_CTRL_D(self):
        """
        """
        log.msg('Received CTRL-D, exiting..')

        cmdclass =  self.protocol.commands['exit']
        pp = CowrieProcessProtocol(self.protocol, cmdclass, None, None, None)
        self.protocol.call_command(pp, self.protocol.commands['exit'])


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
                self.protocol.terminal.write('\n')
                maxlen = max([len(x[fs.A_NAME]) for x in files]) + 1
                perline = int(self.protocol.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.protocol.terminal.write('\n')
                    self.protocol.terminal.write(file[fs.A_NAME].ljust(maxlen))
                    count += 1
                self.protocol.terminal.write('\n')
                self.showPrompt()

        self.protocol.lineBuffer = list(newbuf)
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbuf)



class CowrieProcess(object):
    """
    Model this on spawnProcess()
    --
    Note: protocol is not the ProcessProtocol it's the the terminal protocol now
    """

    def __init__(self, protocol, cmdclass, cmd, next_command, env={}):
        """
        """
        self.protocol = protocol
        self.stdout = CowrieProcessProtocol(self, self.protocol, cmd)
        self.cmd_name = cmd['argv'][0]
        self.cmd_type = cmd['type']
        self.cmdargs = cmd['argv'][1:]
        self.cmd = cmdclass
        self.input_data = ""
        self.next_command = next_command
        self.env = env
        self.data = ""
        self.err_data = ""


    def setInputData(self, data):
        """
        """
        self.data = self.data + data


    def addToStack(self):
        """
        """
        self.runningCommand = self.cmd(self.stdout, self.protocol, *self.cmdargs)
        self.runningCommand.set_process_type(self.cmd_type)
        self.protocol.cmdstack.append(self.runningCommand)


    def removeFromStack(self):
        """
        """
        if not self.cmd_name == 'exit':
            service = self.protocol.cmdstack.pop(self.protocol.cmdstack.index(self.runningCommand))


    def getCommandInstance(self):
        """
        """
        return self.protocol.cmdstack[self.protocol.cmdstack.index(self.runningCommand)]


    def callNextCommand(self):
        """
        """
        if self.next_command:
            self.next_command.input_data = self.data
            npcmd = self.next_command.cmd
            npcmdargs = self.next_command.cmdargs
            self.protocol.pp = self.next_command
            self.protocol.call_command(self.next_command, npcmd, *npcmdargs)


    def insert_command(self, command):
        """
        Insert the next command into the list.
        """
        tmp = self.next_command
        command.next_command = tmp
        self.next_command = command
        self.next_command.addToStack()


    def set_protocol(self, protocol):
        """
        """
        self.protocol = protocol
        self.protocol.pp = self



@implementer(IProcessProtocol)
class CowrieProcessProtocol(object):
    """
    Model this on Twisted ProcessProtocol
    --
    Note: Doesn't work exactly the same!
    """
    __author__ = 'davegermiquet'

    command_list_to_ignore_output = ["sudo", "bash", "sh", "busybox"]

    def __init__(self, process, protocol, commandStructure):
        self.protocol = protocol
        self.commandStructure = commandStructure
        self.process = process
        self.data = ""
        self.err_data = ""


    def outReceived(self, data):
        """
        """
        self.data = self.data + data
        self.process.setInputData(data)
        if not self.commandStructure['type'] == "pipe" and not self.commandStructure['argv'][0] in self.command_list_to_ignore_output:
            if not self.protocol is None and not self.protocol.terminal is None:
                self.protocol.terminal.write(str(data))
            else:
                log.msg("Connection was probably lost. Could not write to terminal")


    def errReceived(self, data):
        """
        """
        self.protocol.terminal.write(data)
        self.err_data = self.err_data + data


    def inConnectionLost(self):
        """
        """
        pass


    def outConnectionLost(self):
        """
        """
        pass


    def errConnectionLost(self):
        """
        """
        pass


    def processExited(self):
        """
        unused
        """
        pass


    def processEnded(self):
        """
        unused
        """
        pass

