# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import absolute_import, division

import copy
import os
import re
import sys

from twisted.internet import error
from twisted.python import failure, log
from twisted.python.compat import iterbytes

from cowrie.shell import fs

# From Python3.6 we get the new shlex version
if sys.version_info.major >= 3 and sys.version_info.minor >= 6:
    import shlex
else:
    from cowrie.shell import shlex


class HoneyPotShell(object):

    def __init__(self, protocol, interactive=True, redirect=False):
        self.protocol = protocol
        self.interactive = interactive
        self.redirect = redirect  # to support output redirection
        self.cmdpending = []
        self.environ = copy.copy(protocol.environ)
        if hasattr(protocol.user, 'windowSize'):
            self.environ['COLUMNS'] = str(protocol.user.windowSize[1])
            self.environ['LINES'] = str(protocol.user.windowSize[0])
        self.lexer = None
        self.showPrompt()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.command.input', input=line, format='CMD: %(input)s')
        self.lexer = shlex.shlex(instream=line, punctuation_chars=True, posix=True)
        # Add these special characters that are not in the default lexer
        self.lexer.wordchars += '@%{}=$:+^,()'
        tokens = []
        parc_tokens = []  # stack of parcial command substitution tokens
        subshell_tokens = []  # stack of subshell tokens
        last_parc_token = False  # control the command substitution tokens processing
        last_subshell_token = False  # control the subshell token processing
        while True:
            try:
                if not last_parc_token:
                    # if we are processing the command substitution dont read token
                    tok = self.lexer.get_token()
                    # log.msg("tok: %s" % (repr(tok)))

                if len(subshell_tokens):
                    if tok:
                        if tok.endswith(')'):
                            subshell_tokens.append(tok[:-1])
                            last_subshell_token = True
                        else:
                            subshell_tokens.append(tok)

                    if not tok or last_subshell_token:
                        cmds = " ".join(subshell_tokens)
                        self.cmdpending.append((subshell_tokens))
                        last_subshell_token = False
                        subshell_tokens = []
                    continue

                if len(parc_tokens):
                    if tok:
                        if tok.endswith(')'):
                            parc_tokens.append(tok[:-1])
                            last_parc_token = True
                        else:
                            parc_tokens.append(tok)

                    if not tok or last_parc_token:
                        cmds = " ".join(parc_tokens)
                        # instantiate new shell with redirect output
                        self.protocol.cmdstack.append(HoneyPotShell(self.protocol, interactive=False, redirect=True))
                        # call lineReceived method that indicates that we have some commands to parse
                        self.protocol.cmdstack[-1].lineReceived(cmds)
                        # remove the shell
                        result = self.protocol.cmdstack.pop()
                        tokens.append(result.protocol.pp.redirected_data.decode()[:-1])
                        last_parc_token = False
                        parc_tokens = []

                    continue

                if tok == self.lexer.eof:
                    if tokens:
                        self.cmdpending.append((tokens))
                        tokens = []
                    break
                """
                Why do we ignore parentheses?
                We cant have this for shell command substitution  to work
                # Ignore parentheses
                tok_len = len(tok)
                tok = tok.strip('(')
                tok = tok.strip(')')
                if len(tok) != tok_len and tok == '':
                    continue
                """
                # For now, treat && and || same as ;, just execute without checking return code
                if tok == '&&' or tok == '||':
                    if tokens:
                        self.cmdpending.append((tokens))
                        tokens = []
                        continue
                    else:
                        self.protocol.terminal.write(
                            '-bash: syntax error near unexpected token `{}\'\n'.format(tok).encode('utf8'))
                        break
                elif tok == ';':
                    if tokens:
                        self.cmdpending.append((tokens))
                        tokens = []
                        continue
                    else:
                        self.protocol.terminal.write(
                            '-bash: syntax error near unexpected token `{}\'\n'.format(tok).encode('utf8'))
                        break
                elif tok == '$?':
                    tok = "0"

                elif tok[0] == '(':
                    subshell_tokens.append(tok[1:])
                    if tok[-1] == ')':
                        last_parc_token = True
                        tok = None
                    continue

                elif tok[0] == '$':
                    envRex = re.compile(r'^\$\(([_a-zA-Z0-9]+)*')
                    envSearch = envRex.search(tok)
                    if envSearch is not None:
                        envMatch = envSearch.group(1)
                        parc_tokens.append(envMatch)
                        if tok[-1] == ')':
                            last_parc_token = True
                            tok = None
                        continue
                    envRex = re.compile(r'^\$([_a-zA-Z0-9]+)$')
                    envSearch = envRex.search(tok)
                    if envSearch is not None:
                        envMatch = envSearch.group(1)
                        if envMatch in list(self.environ.keys()):
                            tok = self.environ[envMatch]
                        else:
                            continue
                    envRex = re.compile(r'^\${([_a-zA-Z0-9]+)}$')
                    envSearch = envRex.search(tok)
                    if envSearch is not None:
                        envMatch = envSearch.group(1)
                        if envMatch in list(self.environ.keys()):
                            tok = self.environ[envMatch]
                        else:
                            continue
                tokens.append(tok)
            except Exception as e:
                self.protocol.terminal.write(
                    b'-bash: syntax error: unexpected end of file\n')
                # Could run runCommand here, but i'll just clear the list instead
                log.msg("exception: {}".format(e))
                self.cmdpending = []
                self.showPrompt()
                return
        if self.cmdpending:
            self.runCommand()
        else:
            self.showPrompt()

    def runCommand(self):
        pp = None

        def runOrPrompt():
            if self.cmdpending:
                self.runCommand()
            else:
                self.showPrompt()

        def parse_arguments(arguments):
            parsed_arguments = []
            for arg in arguments:
                parsed_arguments.append(arg)

            return parsed_arguments

        def parse_file_arguments(arguments):
            """
            Look up arguments in the file system
            """
            parsed_arguments = []
            for arg in arguments:
                matches = self.protocol.fs.resolve_path_wc(arg, self.protocol.cwd)
                if matches:
                    parsed_arguments.extend(matches)
                else:
                    parsed_arguments.append(arg)

            return parsed_arguments

        if not self.cmdpending:
            if self.protocol.pp.next_command is None:  # command dont have pipe(s)
                if self.interactive:
                    self.showPrompt()
                else:
                    # when commands passed to a shell via PIPE, we spawn a HoneyPotShell in none interactive mode
                    # if there are another shells on stack (cmdstack), let's just exit our new shell
                    # else close connection
                    if len(self.protocol.cmdstack) == 1:
                        ret = failure.Failure(error.ProcessDone(status=""))
                        self.protocol.terminal.transport.processEnded(ret)
                    else:
                        return
            else:
                pass  # command with pipes
            return

        cmdAndArgs = self.cmdpending.pop(0)
        cmd2 = copy.copy(cmdAndArgs)

        # Probably no reason to be this comprehensive for just PATH...
        environ = copy.copy(self.environ)
        cmd_array = []
        cmd = {}
        while cmdAndArgs:
            piece = cmdAndArgs.pop(0)
            if piece.count('='):
                key, value = piece.split('=', 1)
                environ[key] = value
                continue
            cmd['command'] = piece
            cmd['rargs'] = []
            break

        if 'command' not in cmd or not cmd['command']:
            runOrPrompt()
            return

        pipe_indices = [i for i, x in enumerate(cmdAndArgs) if x == "|"]
        multipleCmdArgs = []
        pipe_indices.append(len(cmdAndArgs))
        start = 0

        # Gather all arguments with pipes

        for index, pipe_indice in enumerate(pipe_indices):
            multipleCmdArgs.append(cmdAndArgs[start:pipe_indice])
            start = pipe_indice + 1

        cmd['rargs'] = parse_arguments(multipleCmdArgs.pop(0))
        # parse_file_arguments parses too much. should not parse every argument
        # cmd['rargs'] = parse_file_arguments(multipleCmdArgs.pop(0))
        cmd_array.append(cmd)
        cmd = {}

        for index, value in enumerate(multipleCmdArgs):
            cmd['command'] = value.pop(0)
            cmd['rargs'] = parse_arguments(value)
            cmd_array.append(cmd)
            cmd = {}

        lastpp = None
        for index, cmd in reversed(list(enumerate(cmd_array))):

            cmdclass = self.protocol.getCommand(cmd['command'], environ['PATH'].split(':'))
            if cmdclass:
                log.msg(input=cmd['command'] + " " + ' '.join(cmd['rargs']), format='Command found: %(input)s')
                if index == len(cmd_array) - 1:
                    lastpp = StdOutStdErrEmulationProtocol(self.protocol, cmdclass, cmd['rargs'], None, None,
                                                           self.redirect)
                    pp = lastpp
                else:
                    pp = StdOutStdErrEmulationProtocol(self.protocol, cmdclass, cmd['rargs'], None, lastpp,
                                                       self.redirect)
                    lastpp = pp
            else:
                log.msg(eventid='cowrie.command.failed', input=' '.join(cmd2), format='Command not found: %(input)s')
                self.protocol.terminal.write('-bash: {}: command not found\n'.format(cmd['command']).encode('utf8'))
                runOrPrompt()
                pp = None  # Got a error. Don't run any piped commands
                break
        if pp:
            self.protocol.call_command(pp, cmdclass, *cmd_array[0]['rargs'])

    def resume(self):
        if self.interactive:
            self.protocol.setInsertMode()
        self.runCommand()

    def showPrompt(self):
        if not self.interactive:
            return

        cwd = self.protocol.cwd
        homelen = len(self.protocol.user.avatar.home)
        if cwd == self.protocol.user.avatar.home:
            cwd = '~'
        elif len(cwd) > (homelen + 1) and \
                cwd[:(homelen + 1)] == self.protocol.user.avatar.home + '/':
            cwd = '~' + cwd[homelen:]

        # Example: [root@svr03 ~]#   (More of a "CentOS" feel)
        # Example: root@svr03:~#     (More of a "Debian" feel)
        prompt = '{0}@{1}:{2}'.format(self.protocol.user.username, self.protocol.hostname, cwd)
        if not self.protocol.user.uid:
            prompt += '# '  # "Root" user
        else:
            prompt += '$ '  # "Non-Root" user

        self.protocol.terminal.write(prompt.encode('ascii'))
        self.protocol.ps = (prompt.encode('ascii'), b'> ')

    def eofReceived(self):
        """
        this should probably not go through ctrl-d, but use processprotocol to close stdin
        """
        log.msg("received eof, sending ctrl-d to command")
        if self.cmdstack:
            self.cmdstack[-1].handle_CTRL_D()

    def handle_CTRL_C(self):
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.write(b'\n')
        self.showPrompt()

    def handle_CTRL_D(self):
        log.msg('Received CTRL-D, exiting..')

        cmdclass = self.protocol.commands['exit']
        pp = StdOutStdErrEmulationProtocol(self.protocol, cmdclass, None, None, None)
        self.protocol.call_command(pp, self.protocol.commands['exit'])

    def handle_TAB(self):
        """
        lineBuffer is an array of bytes
        """
        if not self.protocol.lineBuffer:
            return

        line = b''.join(self.protocol.lineBuffer)
        if line[-1] == b' ':
            clue = ''
        else:
            clue = line.split()[-1].decode('utf8')
        # clue now contains the string to complete or is empty.
        # line contains the buffer as bytes

        try:
            basedir = os.path.dirname(clue)
        except Exception:
            pass
        if basedir and basedir[-1] != '/':
            basedir += '/'

        files = []
        tmppath = basedir
        if not basedir:
            tmppath = self.protocol.cwd
        try:
            r = self.protocol.fs.resolve_path(tmppath, self.protocol.cwd)
        except Exception:
            return
        for x in self.protocol.fs.get_path(r):
            if clue == '':
                files.append(x)
                continue
            if not x[fs.A_NAME].startswith(os.path.basename(clue)):
                continue
            files.append(x)

        if not files:
            return

        # Clear early so we can call showPrompt if needed
        for i in range(self.protocol.lineBufferIndex):
            self.protocol.terminal.cursorBackward()
            self.protocol.terminal.deleteCharacter()

        newbuf = ''
        if len(files) == 1:
            newbuf = ' '.join(line.decode('utf8').split()[:-1] + ['%s%s' % (basedir, files[0][fs.A_NAME])])
            if files[0][fs.A_TYPE] == fs.T_DIR:
                newbuf += '/'
            else:
                newbuf += ' '
            newbuf = newbuf.encode('utf8')
        else:
            if os.path.basename(clue):
                prefix = os.path.commonprefix([x[fs.A_NAME] for x in files])
            else:
                prefix = ''
            first = line.decode('utf8').split(' ')[:-1]
            newbuf = ' '.join(first + ['%s%s' % (basedir, prefix)])
            newbuf = newbuf.encode('utf8')
            if newbuf == b''.join(self.protocol.lineBuffer):
                self.protocol.terminal.write(b'\n')
                maxlen = max([len(x[fs.A_NAME]) for x in files]) + 1
                perline = int(self.protocol.user.windowSize[1] / (maxlen + 1))
                count = 0
                for file in files:
                    if count == perline:
                        count = 0
                        self.protocol.terminal.write(b'\n')
                    self.protocol.terminal.write(file[fs.A_NAME].ljust(maxlen).encode('utf8'))
                    count += 1
                self.protocol.terminal.write(b'\n')
                self.showPrompt()

        self.protocol.lineBuffer = [y for x, y in enumerate(iterbytes(newbuf))]
        self.protocol.lineBufferIndex = len(self.protocol.lineBuffer)
        self.protocol.terminal.write(newbuf)


class StdOutStdErrEmulationProtocol(object):
    """
    Pipe support written by Dave Germiquet
    Support for commands chaining added by Ivan Korolev (@fe7ch)
    """
    __author__ = 'davegermiquet'

    def __init__(self, protocol, cmd, cmdargs, input_data, next_command, redirect=False):
        self.cmd = cmd
        self.cmdargs = cmdargs
        self.input_data = input_data
        self.next_command = next_command
        self.data = b""
        self.redirected_data = b""
        self.err_data = b""
        self.protocol = protocol
        self.redirect = redirect  # dont send to terminal if enabled

    def connectionMade(self):

        self.input_data = None

    def outReceived(self, data):
        """
        Invoked when a command in the chain called 'write' method
        If we have a next command, pass the data via input_data field
        Else print data to the terminal
        """
        self.data = data

        if not self.next_command:
            if not self.redirect:
                if self.protocol is not None and self.protocol.terminal is not None:
                    self.protocol.terminal.write(data)
                else:
                    log.msg("Connection was probably lost. Could not write to terminal")
            else:
                self.redirected_data += self.data
        else:
            if self.next_command.input_data is None:
                self.next_command.input_data = self.data
            else:
                self.next_command.input_data += self.data

    def insert_command(self, command):
        """
        Insert the next command into the list.
        """
        command.next_command = self.next_command
        self.next_command = command

    def errReceived(self, data):
        if self.protocol and self.protocol.terminal:
            self.protocol.terminal.write(data)
        self.err_data = self.err_data + data

    def inConnectionLost(self):
        pass

    def outConnectionLost(self):
        """
        Called from HoneyPotBaseProtocol.call_command() to run a next command in the chain
        """

        if self.next_command:
            # self.next_command.input_data = self.data
            npcmd = self.next_command.cmd
            npcmdargs = self.next_command.cmdargs
            self.protocol.call_command(self.next_command, npcmd, *npcmdargs)

    def errConnectionLost(self):
        pass

    def processExited(self, reason):
        log.msg("processExited for %s, status %d" % (self.cmd, reason.value.exitCode))

    def processEnded(self, reason):
        log.msg("processEnded for %s, status %d" % (self.cmd, reason.value.exitCode))
