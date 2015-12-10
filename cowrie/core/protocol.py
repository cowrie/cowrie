# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import os
import time
import socket
import hashlib

from twisted.python import failure, log
from twisted.internet import error
from twisted.protocols.policies import TimeoutMixin

from twisted.conch import recvline
from twisted.conch.insults import insults

from cowrie.core import honeypot
from cowrie.core import ttylog
from cowrie.core import utils

class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    """

    def __init__(self, avatar):
        self.user = avatar
        self.environ = avatar.environ
        self.cfg = self.user.cfg
        self.hostname = avatar.server.hostname
        self.fs = avatar.server.fs
        if self.fs.exists(avatar.avatar.home):
            self.cwd = avatar.avatar.home
        else:
            self.cwd = '/'

        self.commands = {}
        import cowrie.commands
        for c in cowrie.commands.__all__:
            module = __import__('cowrie.commands.%s' % (c,),
                globals(), locals(), ['commands'])
            self.commands.update(module.commands)

        self.password_input = False
        self.cmdstack = []


    def logDispatch(self, *msg, **args):
        """
        """
        transport = self.terminal.transport.session.conn.transport
        args['sessionno'] = transport.transport.sessionno
        transport.factory.logDispatch(*msg, **args)


    def connectionMade(self):
        """
        """


        transport = self.terminal.transport.session.conn.transport

        self.realClientIP = transport.transport.getPeer().host
        self.realClientPort = transport.transport.getPeer().port
        self.clientVersion = transport.otherVersionString
        self.logintime = time.time()
        self.setTimeout(1800)

        # Source IP of client in user visible reports (can be fake or real)
        try:
            self.clientIP = self.cfg.get('honeypot', 'fake_addr')
        except:
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
        """
	this logs out when connection times out
        """
        self.writeln( 'timed out waiting for input: auto-logout' )
        ret = failure.Failure(error.ProcessTerminated(exitCode=1))
        self.terminal.transport.processEnded(ret)


    def eofReceived(self):
        """
        this should probably not go through ctrl-d, but use processprotocol to close stdin
        """
        log.msg("received eof, sending ctrl-d to command")
        if len(self.cmdstack):
            self.cmdstack[-1].handle_CTRL_D()


    def connectionLost(self, reason):
        """
        this is only called on explicit logout, not on disconnect
        this indicates the closing of the channel/session, not the closing of the transport
        """
        self.setTimeout(None)
        insults.TerminalProtocol.connectionLost(self, reason)
        self.terminal = None # (this should be done by super above)
        del self.cmdstack
        del self.commands
        self.fs = None
        self.cfg = None
        self.user = None
        log.msg( "honeypot terminal protocol connection lost %s" % reason)


    def txtcmd(self, txt):
        """
        """
        class command_txtcmd(honeypot.HoneyPotCommand):
            def call(self):
                log.msg('Reading txtcmd from "%s"' % txt)
                with open(txt, 'r') as f:
                    self.write(f.read())
        return command_txtcmd


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
            (self.cfg.get('honeypot', 'txtcmds_path'), path))
        if os.path.exists(txt) and os.path.isfile(txt):
            return self.txtcmd(txt)
        if path in self.commands:
            return self.commands[path]
        return None


    def lineReceived(self, line):
        """
        """
        self.resetTimeout()
        if len(self.cmdstack):
            self.cmdstack[-1].lineReceived(line)


    def writeln(self, data):
        """
        Sometimes still called after disconnect because of a deferred
        """
        if self.terminal:
            self.terminal.write(data)
            self.terminal.nextLine()


    def call_command(self, cmd, *args):
        """
        """
        obj = cmd(self, *args)
        self.cmdstack.append(obj)
        obj.start()


    def uptime(self, reset=None):
        """
        """
        transport = self.terminal.transport.session.conn.transport
        r = time.time() - transport.factory.starttime
        if reset:
            transport.factory.starttime = reset
        return r



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
        self.terminal.stdinlog_open = True

        self.cmdstack = [honeypot.HoneyPotShell(self, interactive=False)]
        self.cmdstack[0].lineReceived(self.execcmd)



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
        """
        """
        self.terminal.interactors.append(interactor)


    def delInteractor(self, interactor):
        """
        """
        self.terminal.interactors.remove(interactor)


    def displayMOTD(self):
        """
        """
        try:
            self.writeln(self.fs.file_contents('/etc/motd'))
        except:
            pass


    def lastlogExit(self):
        """
        """
        starttime = time.strftime('%a %b %d %H:%M',
            time.localtime(self.logintime))
        endtime = time.strftime('%H:%M',
            time.localtime(time.time()))
        duration = utils.durationHuman(time.time() - self.logintime)
        with open( '%s/lastlog.txt' % self.cfg.get('honeypot',
            'data_path'), 'a') as f:
            f.write('root\tpts/0\t%s\t%s - %s (%s)\n' % \
                (self.clientIP, starttime, endtime, duration))


    def connectionLost(self, reason):
        """
        this doesn't seem to be called upon disconnect, so please use
        HoneyPotTransport.connectionLost instead
        """
        self.lastlogExit()
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)
        self.keyHandlers = None


    def initializeScreen(self):
        """
        Overriding super to prevent terminal.reset()
        """
        self.setInsertMode()


    def call_command(self, cmd, *args):
        """
        """
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, cmd, *args)


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
                self.historyLines.append(''.join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        return recvline.RecvLine.handle_RETURN(self)


    def handle_CTRL_C(self):
        """
        """
        self.cmdstack[-1].handle_CTRL_C()


    def handle_CTRL_D(self):
        """
        """
        self.cmdstack[-1].handle_CTRL_D()


    def handle_TAB(self):
        """
        """
        self.cmdstack[-1].handle_TAB()


    def handle_CTRL_K(self):
        """
        """
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0:self.lineBufferIndex]


    def handle_CTRL_U(self):
        """
        """
        for _ in range(self.lineBufferIndex):
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
        self.bytesReceived = 0
        self.interactors = []

        try:
            self.bytesReceivedLimit = int(self.cfg.get('honeypot', 'download_limit_size'))
        except:
            self.bytesReceivedLimit = 0

        if prot is HoneyPotExecProtocol:
            self.type = 'e' # execcmd
        else:
            self.type = 'i' # interactive


    def connectionMade(self):
        """
        """
        transportId = self.transport.session.conn.transport.transportId
        channelId = self.transport.session.id

        self.ttylog_file = '%s/tty/%s-%s-%s%s.log' % \
            (self.cfg.get('honeypot', 'log_path'),
            time.strftime('%Y%m%d-%H%M%S'), transportId, channelId,
            self.type)
        ttylog.ttylog_open(self.ttylog_file, time.time())
        self.ttylog_open = True

        log.msg(eventid='KIPP0004', ttylog=self.ttylog_file,
            format='Opening TTY Log: %(ttylog)s')

        self.stdinlog_file = '%s/%s-%s-%s-stdin.log' % \
            (self.cfg.get('honeypot', 'download_path'),
            time.strftime('%Y%m%d-%H%M%S'), transportId, channelId)
        self.stdinlog_open = False

        insults.ServerProtocol.connectionMade(self)


    def write(self, bytes):
        """
        """
        for i in self.interactors:
            i.sessionWrite(bytes)

        if self.ttylog_open:
            ttylog.ttylog_write(self.ttylog_file, len(bytes),
                ttylog.TYPE_OUTPUT, time.time(), bytes)

        insults.ServerProtocol.write(self, bytes)


    def dataReceived(self, data):
        """
        """
        self.bytesReceived += len(data)
        if self.bytesReceivedLimit and self.bytesReceived > self.bytesReceivedLimit:
            log.msg(eventid='KIPP0015', format='Data upload limit reached')
            #self.loseConnection()
            self.eofReceived()
            return

        if self.stdinlog_open:
            with file(self.stdinlog_file, 'ab') as f:
                f.write(data)
        elif self.ttylog_open:
            ttylog.ttylog_write(self.ttylog_file, len(data),
                ttylog.TYPE_INPUT, time.time(), data)

        insults.ServerProtocol.dataReceived(self, data)


    def eofReceived(self):
        """
        """
        if self.terminalProtocol:
            self.terminalProtocol.eofReceived()


    def loseConnection(self):
        """
        override super to remove the terminal reset on logout

        """
        self.transport.loseConnection()


    def connectionLost(self, reason):
        """
        FIXME: this method is called 4 times on logout....
        it's called once from Avatar.closed() if disconnected
        """
        log.msg("received call to LSP.connectionLost")

        for i in self.interactors:
            i.sessionClosed()

        transport = self.transport.session.conn.transport

        if self.stdinlog_open:
            try:
                with open(self.stdinlog_file, 'rb') as f:
                    shasum = hashlib.sha256(f.read()).hexdigest()
                    shasumfile = self.cfg.get('honeypot',
                        'download_path') + "/" + shasum
                    if (os.path.exists(shasumfile)):
                        os.remove(self.stdinlog_file)
                    else:
                        os.rename(self.stdinlog_file, shasumfile)
                    os.symlink(shasum, self.stdinlog_file)
                log.msg(eventid='KIPP0007',
                    format='Saved stdin contents to %(outfile)s',
                    url='stdin', outfile=shasumfile, shasum=shasum)
            except IOError as e:
                pass
            finally:
                self.stdinlog_open = False

        if self.ttylog_open:
            log.msg(eventid='KIPP0012', format='Closing TTY Log: %(ttylog)s',
                ttylog=self.ttylog_file)
            ttylog.ttylog_close(self.ttylog_file, time.time())
            self.ttylog_open = False

        self.cfg = None
        insults.ServerProtocol.connectionLost(self, reason)

# vim: set sw=4 et:
