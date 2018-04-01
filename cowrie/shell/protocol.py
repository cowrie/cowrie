# -*- test-case-name: cowrie.test.protocol -*-
# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import os
import sys
import time
import socket
import traceback
import random

from twisted.python import failure, log
from twisted.internet import error
from twisted.protocols.policies import TimeoutMixin
from twisted.conch import recvline
from twisted.conch.insults import insults

from cowrie.shell import honeypot
from cowrie.core import utils

from cowrie.core.config import CONFIG

class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    Base protocol for interactive and non-interactive use
    """

    def __init__(self, avatar):
        self.user = avatar
        self.environ = avatar.environ
        self.hostname = avatar.server.hostname
        self.fs = avatar.server.fs
        self.pp = None
        self.logintime = None
        self.realClientIP = None
        self.realClientPort = None
        self.clientVersion = None
        self.kippoIP = None
        self.clientIP = None

        if self.fs.exists(avatar.avatar.home):
            self.cwd = avatar.avatar.home
        else:
            self.cwd = '/'
        self.input_data = None
        self.data = None
        self.commands = {}
        import cowrie.commands
        for c in cowrie.commands.__all__:
            try:
                module = __import__('cowrie.commands.%s' % (c,),
                    globals(), locals(), ['commands'])
                self.commands.update(module.commands)
            except Exception as e:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                log.err("Failed to import command {}: {}: {}".format(c, e, ''.join(traceback.format_exception(exc_type,exc_value,exc_traceback))))
        self.password_input = False
        self.cmdstack = []
        

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need provide how we grab
        the proper transport to access underlying SSH information. Meant to be
        overridden for other protocols.
        """
        return self.terminal.transport.session.conn.transport


    def logDispatch(self, *msg, **args):
        """
        Send log directly to factory, avoiding normal log dispatch
        """
        pt = self.getProtoTransport()
        args['sessionno'] = pt.transport.sessionno
        pt.factory.logDispatch(*msg, **args)


    def connectionMade(self):
        """
        """
        pt = self.getProtoTransport()

        self.realClientIP = pt.transport.getPeer().host
        self.realClientPort = pt.transport.getPeer().port
        self.clientVersion = self.getClientVersion()
        self.logintime = time.time()
        
        try:
            timeout = CONFIG.getint('honeypot', 'interactive_timeout')
        except:
            timeout = 180
        self.setTimeout(timeout)

        # Source IP of client in user visible reports (can be fake or real)
        try:
            self.clientIP = CONFIG.get('honeypot', 'fake_addr')
        except:
            self.clientIP = self.realClientIP

        if CONFIG.has_option('honeypot', 'internet_facing_ip'):
            self.kippoIP = CONFIG.get('honeypot', 'internet_facing_ip')
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                self.kippoIP = s.getsockname()[0]
            except:
                self.kippoIP = '192.168.0.1'
            finally:
                s.close()


    def timeoutConnection(self):
        """
        this logs out when connection times out
        """
        ret = failure.Failure(error.ProcessTerminated(exitCode=1))
        self.terminal.transport.processEnded(ret)


    def connectionLost(self, reason):
        """
        Called when the connection is shut down.
        Clear any circular references here, and any external references to
        this Protocol. The connection has been closed.
        """
        self.setTimeout(None)
        insults.TerminalProtocol.connectionLost(self, reason)
        self.terminal = None # (this should be done by super above)
        del self.cmdstack
        del self.commands
        self.fs = None
        self.pp = None
        self.user = None
        self.environ = None
        #log.msg("honeypot terminal protocol connection lost {}".format(reason))


    def txtcmd(self, txt):
        """
        """
        class command_txtcmd(honeypot.HoneyPotCommand):
            def call(self):
                log.msg('Reading txtcmd from "{}"'.format(txt))
                with open(txt, 'r') as f:
                    self.write(f.read())
        return command_txtcmd


    def isCommand(self, cmd):
        """
        Check if cmd (the argument of a command) is a command, too.
        """
        return True if cmd in self.commands else False


    def getCommand(self, cmd, paths):
        """
        """
        if not len(cmd.strip()):
            return None
        path = None
        if cmd in self.commands:
            return self.commands[cmd]
        if cmd[0] in ('.', '/'):
            path = self.fs.resolve_path(cmd, self.cwd)
            if not self.fs.exists(path):
                return None
        else:
            for i in ['%s/%s' % (self.fs.resolve_path(x, self.cwd), cmd) \
                    for x in paths]:
                if self.fs.exists(i):
                    path = i
                    break

        txt = os.path.normpath('%s/%s' % \
            (CONFIG.get('honeypot', 'txtcmds_path'), path))
        if os.path.exists(txt) and os.path.isfile(txt):
            return self.txtcmd(txt)

        if path in self.commands:
            return self.commands[path]

        return None


    def lineReceived(self, line):
        """
        Line Received
        """
        # Turn idle timeout into time-based timout by commenting out reset
        #self.resetTimeout()
        if len(self.cmdstack):
            self.cmdstack[-1].lineReceived(line)


    def call_command(self, pp, cmd, *args):
        """
        """
        self.pp = pp
        obj = cmd(self, *args)
        obj.set_input_data(pp.input_data)
        self.cmdstack.append(obj)
        obj.start()

        if self.pp:
            self.pp.outConnectionLost()


    def uptime(self):
        """
        Uptime
        """
        pt = self.getProtoTransport()
        r = time.time() - pt.factory.starttime
        #if reset:
        #    pt.factory.starttime = reset
        return r


    def getClientVersion(self):
        pt = self.getProtoTransport()
        return pt.otherVersionString


    def eofReceived(self):
        # Shell received EOF, nicely exit
        """
        TODO: this should probably not go through transport, but use processprotocol to close stdin
        """
        ret = failure.Failure(error.ProcessTerminated(exitCode=0))
        self.terminal.transport.processEnded(ret)



class HoneyPotExecProtocol(HoneyPotBaseProtocol):
    """
    """

    def __init__(self, avatar, execcmd):
        self.execcmd = execcmd
        HoneyPotBaseProtocol.__init__(self, avatar)


    def connectionMade(self):
        """
        """
        HoneyPotBaseProtocol.connectionMade(self)
        self.setTimeout(60)
        self.cmdstack = [honeypot.HoneyPotShell(self, interactive=False)]
        self.cmdstack[0].lineReceived(self.execcmd)


    def eofReceived(self):
        """
        Received EOF, run command to finish and then exit
        """
        log.msg("received eof, sending ctrl-d to command")
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_D()


class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):
    """
    """

    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, avatar)


    def connectionMade(self):
        """
        """
        self.displayMOTD()

        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)

        self.cmdstack = [honeypot.HoneyPotShell(self)]

        self.keyHandlers.update({
            '\x01':     self.handle_HOME,	# CTRL-A
            '\x02':     self.handle_LEFT,	# CTRL-B
            '\x03':     self.handle_CTRL_C,	# CTRL-C
            '\x04':     self.handle_CTRL_D,	# CTRL-D
            '\x05':     self.handle_END,	# CTRL-E
            '\x06':     self.handle_RIGHT,	# CTRL-F
            '\x08':     self.handle_BACKSPACE,	# CTRL-H
            '\x09':     self.handle_TAB,
            '\x0b':     self.handle_CTRL_K,	# CTRL-K
            '\x0c':     self.handle_CTRL_L,	# CTRL-L
            '\x0e':     self.handle_DOWN,	# CTRL-N
            '\x10':     self.handle_UP,		# CTRL-P
            '\x15':     self.handle_CTRL_U,	# CTRL-U
            '\x16':     self.handle_CTRL_V,	# CTRL-V
            '\x1b':     self.handle_ESC,	# ESC
            })


    def displayMOTD(self):
        """
        """
        try:
            self.terminal.write(self.fs.file_contents('/etc/motd')+'\n')

        except:
            pass


    def timeoutConnection(self):
        """
        this logs out when connection times out
        """
        self.terminal.write( b'timed out waiting for input: auto-logout\n' )
        HoneyPotBaseProtocol.timeoutConnection(self)


    def connectionLost(self, reason):
        """
        """
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)
        self.keyHandlers = None


    def initializeScreen(self):
        """
        Overriding super to prevent terminal.reset()
        """
        self.setInsertMode()


    def call_command(self, pp, cmd, *args):
        """
        """
        self.pp = pp
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, pp, cmd, *args)


    def characterReceived(self, ch, moreCharactersComing):
        """
        Easier way to implement password input?
        """
        if self.mode == 'insert':
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex:self.lineBufferIndex+1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input:
            self.terminal.write(ch)


    def handle_RETURN(self):
        """
        """
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                self.historyLines.append(b''.join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        return recvline.RecvLine.handle_RETURN(self)


    def handle_CTRL_C(self):
        """
        """
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_C()


    def handle_CTRL_D(self):
        """
        """
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_D()


    def handle_TAB(self):
        """
        """
        if len(self.cmdstack):
            self.cmdstack[-1].handle_TAB()


    def handle_CTRL_K(self):
        """
        """
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0:self.lineBufferIndex]


    def handle_CTRL_L(self):
        """
        Handle a 'form feed' byte - generally used to request a screen
        refresh/redraw.
        """
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()


    def handle_CTRL_U(self):
        """
        """
        for _ in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex:]
        self.lineBufferIndex = 0


    def handle_CTRL_V(self):
        """
        """
        pass


    def handle_ESC(self):
        """
        """
        pass


class HoneyPotInteractiveTelnetProtocol(HoneyPotInteractiveProtocol):
    """
    Specialized HoneyPotInteractiveProtocol that provides Telnet specific
    overrides.
    """

    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotInteractiveProtocol.__init__(self, avatar)

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need to override how we grab
        the proper transport to access underlying Telnet information.
        """
        return self.terminal.transport.session.transport

    def getClientVersion(self):
        return 'Telnet'
