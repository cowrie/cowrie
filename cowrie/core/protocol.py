# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import os
import time
import socket
import copy

from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.python import log
from twisted.protocols.policies import TimeoutMixin

from . import honeypot
from . import ttylog
from . import utils

class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):

    def __init__(self, avatar):
        self.user = avatar
        self.cfg = self.user.cfg
        self.hostname = avatar.server.hostname
        self.fs = avatar.server.fs
        if self.fs.exists(avatar.home):
            self.cwd = avatar.home
        else:
            self.cwd = '/'

        # commands is also a copy so we can add stuff on the fly
        # self.commands = copy.copy(self.commands)
	self.commands = {}
        import cowrie.commands
        for c in cowrie.commands.__all__:
            module = __import__('cowrie.commands.%s' % (c,),
                globals(), locals(), ['commands'])
            self.commands.update(module.commands)

        self.password_input = False
        self.cmdstack = []

    def logDispatch(self, *msg, **args):
        transport = self.terminal.transport.session.conn.transport
        args['sessionno'] = transport.transport.sessionno
        transport.factory.logDispatch(*msg, **args)

    def connectionMade(self):
        transport = self.terminal.transport.session.conn.transport

        self.realClientIP = transport.transport.getPeer().host
        self.realClientPort = transport.transport.getPeer().port
        self.clientVersion = transport.otherVersionString
        self.logintime = time.time()
        self.setTimeout(1800)

        # source IP of client in user visible reports (can be fake or real)
        if self.cfg.has_option('honeypot', 'fake_addr'):
            self.clientIP = self.cfg.get('honeypot', 'fake_addr')
        else:
            self.clientIP = self.realClientIP

        if self.cfg.has_option('honeypot', 'internet_facing_ip'):
            self.kippoIP = self.cfg.get('honeypot', 'internet_facing_ip')
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
        self.writeln( 'timed out waiting for input: auto-logout' )
        self.terminal.transport.session.sendEOF()
        self.terminal.transport.session.sendClose()

    # this is only called on explicit logout, not on disconnect
    # this indicates the closing of the channel/session, not the closing of the transport
    def connectionLost(self, reason):
	self.terminal = None # (this should be done by super below)
	insults.TerminalProtocol.connectionLost(self, reason)
	del self.cmdstack
	del self.commands
	self.fs = None
	self.cfg = None
	self.user = None
        log.msg( "honeypot terminal protocol connection lost %s" % reason)

    def txtcmd(self, txt):
        class command_txtcmd(honeypot.HoneyPotCommand):
            def call(self):
                log.msg('Reading txtcmd from "%s"' % txt)
                with open(txt, 'r') as f:
                    self.write(f.read())
        return command_txtcmd

    def getCommand(self, cmd, paths):
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
            (self.cfg.get('honeypot', 'txtcmds_path'), path))
        if os.path.exists(txt) and os.path.isfile(txt):
            return self.txtcmd(txt)
        if path in self.commands:
            return self.commands[path]
        return None

    def lineReceived(self, line):
        self.resetTimeout()
        if len(self.cmdstack):
            self.cmdstack[-1].lineReceived(line)

    def writeln(self, data):
        self.terminal.write(data)
        self.terminal.nextLine()

    def call_command(self, cmd, *args):
        obj = cmd(self, *args)
        self.cmdstack.append(obj)
        obj.start()

    def uptime(self, reset=None):
        transport = self.terminal.transport.session.conn.transport
        r = time.time() - transport.factory.starttime
        if reset:
            transport.factory.starttime = reset
        return r

class HoneyPotExecProtocol(HoneyPotBaseProtocol):

    def __init__(self, avatar, execcmd):
        self.execcmd = execcmd
        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self):
        HoneyPotBaseProtocol.connectionMade(self)
        self.setTimeout(60)
        self.terminal.stdinlog_open = True

        self.cmdstack = [honeypot.HoneyPotShell(self, interactive=False)]
        self.cmdstack[0].lineReceived(self.execcmd)


class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):

    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self):
        self.displayMOTD()
        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)

        self.cmdstack = [honeypot.HoneyPotShell(self)]

        transport = self.terminal.transport.session.conn.transport
        transport.factory.sessions[transport.transport.sessionno] = self

        self.keyHandlers.update({
            '\x01':     self.handle_HOME,	# CTRL-A
            '\x02':     self.handle_LEFT,	# CTRL-B
            '\x03':     self.handle_CTRL_C,	# CTRL-C
            '\x04':     self.handle_CTRL_D,	# CTRL-D
            '\x05':     self.handle_END,	# CTRL-E
            '\x06':     self.handle_RIGHT,	# CTRL-F
            '\x09':     self.handle_TAB,
            '\x0B':     self.handle_CTRL_K,	# CTRL-K
            '\x0E':     self.handle_DOWN,	# CTRL-N
            '\x10':     self.handle_UP,		# CTRL-P
            '\x15':     self.handle_CTRL_U,	# CTRL-U
            })

    def addInteractor(self, interactor):
        transport = self.terminal.transport.session.conn.transport
        transport.interactors.append(interactor)

    def delInteractor(self, interactor):
        transport = self.terminal.transport.session.conn.transport
        transport.interactors.remove(interactor)

    def displayMOTD(self):
        try:
            self.writeln(self.fs.file_contents('/etc/motd'))
        except:
            pass

    def lastlogExit(self):
        starttime = time.strftime('%a %b %d %H:%M',
            time.localtime(self.logintime))
        endtime = time.strftime('%H:%M',
            time.localtime(time.time()))
        duration = utils.durationHuman(time.time() - self.logintime)
	with open( '%s/lastlog.txt' % self.cfg.get('honeypot', 'data_path'), 'a') as f:
            f.write('root\tpts/0\t%s\t%s - %s (%s)\n' % \
                (self.clientIP, starttime, endtime, duration))

    # this doesn't seem to be called upon disconnect, so please use
    # HoneyPotTransport.connectionLost instead
    def connectionLost(self, reason):
        self.lastlogExit()
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)

    # Overriding to prevent terminal.reset()
    def initializeScreen(self):
        self.setInsertMode()

    def call_command(self, cmd, *args):
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, cmd, *args)

    # Easier way to implement password input?
    def characterReceived(self, ch, moreCharactersComing):
        if self.mode == 'insert':
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex:self.lineBufferIndex+1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input:
            self.terminal.write(ch)

    def handle_RETURN(self):
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                self.historyLines.append(''.join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        return recvline.RecvLine.handle_RETURN(self)

    def handle_CTRL_C(self):
        self.cmdstack[-1].handle_CTRL_C()

    def handle_CTRL_D(self):
        self.cmdstack[-1].handle_CTRL_D()

    def handle_TAB(self):
        self.cmdstack[-1].handle_TAB()

    def handle_CTRL_K(self):
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0:self.lineBufferIndex]

    def handle_CTRL_U(self):
        for i in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex:]
        self.lineBufferIndex = 0

class LoggingServerProtocol(insults.ServerProtocol):
    """
    Wrapper for ServerProtocol that implements TTY logging
    """

    def __init__(self, prot=None, *a, **kw):
        insults.ServerProtocol.__init__(self, prot, *a, **kw)
        self.cfg = a[0].cfg

    def connectionMade(self):
        transport = self.transport.session.conn.transport

        transport.ttylog_file = '%s/tty/%s-%s.log' % \
            (self.cfg.get('honeypot', 'log_path'),
            time.strftime('%Y%m%d-%H%M%S'), transport.transportId)

        self.ttylog_file = transport.ttylog_file
        log.msg(eventid='KIPP0004', ttylog=transport.ttylog_file,
            format='Opening TTY Log: %(ttylog)s')

        ttylog.ttylog_open(transport.ttylog_file, time.time())
        self.ttylog_open = True

        self.stdinlog_file = '%s/%s-%s-stdin.log' % \
            (self.cfg.get('honeypot', 'download_path'),
            time.strftime('%Y%m%d-%H%M%S'), transport.transportId)
        self.stdinlog_open = False

        insults.ServerProtocol.connectionMade(self)

    def write(self, bytes, noLog=False):
        transport = self.transport.session.conn.transport
        for i in transport.interactors:
            i.sessionWrite(bytes)
        if self.ttylog_open and not noLog:
            ttylog.ttylog_write(transport.ttylog_file, len(bytes),
                ttylog.TYPE_OUTPUT, time.time(), bytes)

        insults.ServerProtocol.write(self, bytes)

    def dataReceived(self, data, noLog=False):
        transport = self.transport.session.conn.transport
        if self.ttylog_open and not noLog:
            ttylog.ttylog_write(transport.ttylog_file, len(data),
                ttylog.TYPE_INPUT, time.time(), data)
        if self.stdinlog_open and not noLog:
            log.msg("Saving %s bytes to stdin log: %s" % ( len(data), self.stdinlog_file))
            f = file(self.stdinlog_file, 'ab')
            f.write(data)
            f.close

        insults.ServerProtocol.dataReceived(self, data)

    # override super to remove the terminal reset on logout
    def loseConnection(self):
        self.transport.loseConnection()

    # FIXME: this method is called 4 times on logout....
    # it's called once from Avatar.closed() if disconnected
    def connectionLost(self, reason):
	self.cfg = None
        log.msg("received call to LSP.connectionLost")
        transport = self.transport.session.conn.transport
        if self.ttylog_open:
            log.msg(eventid='KIPP0012', format='Closing TTY Log: %(ttylog)s',
                ttylog=transport.ttylog_file)
            ttylog.ttylog_close(transport.ttylog_file, time.time())
            self.ttylog_open = False
        insults.ServerProtocol.connectionLost(self, reason)

# vim: set sw=4 et:
