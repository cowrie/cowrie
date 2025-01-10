# -*- test-case-name: cowrie.test.protocol -*-
# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from __future__ import annotations

from importlib import import_module
import os
import socket
import sys
import time
import traceback
from typing import ClassVar

from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.internet import error
from twisted.internet.protocol import connectionDone
from twisted.protocols.policies import TimeoutMixin
from twisted.python import failure, log

import cowrie.commands
from cowrie.core.config import CowrieConfig
from cowrie.shell import command, honeypot


class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    Base protocol for interactive and non-interactive use
    """

    commands: ClassVar[dict] = {}
    for c in cowrie.commands.__all__:
        try:
            module = import_module(f"cowrie.commands.{c}")
            commands.update(module.commands)
        except ImportError as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            log.err(
                "Failed to import command {}: {}: {}".format(
                    c,
                    e,
                    "".join(
                        traceback.format_exception(exc_type, exc_value, exc_traceback)
                    ),
                )
            )

    def __init__(self, avatar):
        self.user = avatar
        self.environ = avatar.environ
        self.hostname: str = self.user.server.hostname
        self.fs = self.user.server.fs
        self.pp = None
        self.logintime: float
        self.realClientIP: str
        self.realClientPort: int
        self.kippoIP: str
        self.clientIP: str
        self.sessionno: int
        self.factory = None

        if self.fs.exists(self.user.avatar.home):
            self.cwd = self.user.avatar.home
        else:
            self.cwd = "/"
        self.data = None
        self.password_input = False
        self.cmdstack = []

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need provide how we grab
        the proper transport to access underlying SSH information. Meant to be
        overridden for other protocols.
        """
        return self.terminal.transport.session.conn.transport

    def logDispatch(self, **args):
        """
        Send log directly to factory, avoiding normal log dispatch
        """
        args["sessionno"] = self.sessionno
        self.factory.logDispatch(**args)

    def connectionMade(self) -> None:
        pt = self.getProtoTransport()

        self.factory = pt.factory
        self.sessionno = pt.transport.sessionno
        self.realClientIP = pt.transport.getPeer().host
        self.realClientPort = pt.transport.getPeer().port
        self.logintime = time.time()

        log.msg(eventid="cowrie.session.params", arch=self.user.server.arch)

        idle_timeout = CowrieConfig.getint("honeypot", "idle_timeout", fallback=180)
        self.setTimeout(idle_timeout)

        # Source IP of client in user visible reports (can be fake or real)
        self.clientIP = CowrieConfig.get(
            "honeypot", "fake_addr", fallback=self.realClientIP
        )

        # Source IP of server in user visible reports (can be fake or real)
        if CowrieConfig.has_option("honeypot", "internet_facing_ip"):
            self.kippoIP = CowrieConfig.get("honeypot", "internet_facing_ip")
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    self.kippoIP = s.getsockname()[0]
            except Exception:
                self.kippoIP = "192.168.0.1"

    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        ret = failure.Failure(error.ProcessTerminated(exitCode=1))
        self.terminal.transport.processEnded(ret)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        """
        Called when the connection is shut down.
        Clear any circular references here, and any external references to
        this Protocol. The connection has been closed.
        """
        self.setTimeout(None)
        insults.TerminalProtocol.connectionLost(self, reason)
        self.terminal = None  # (this should be done by super above)
        self.cmdstack = []
        self.fs = None
        self.pp = None
        self.user = None
        self.environ = None

    def txtcmd(self, txt: str) -> object:
        class Command_txtcmd(command.HoneyPotCommand):
            def call(self):
                log.msg(f'Reading txtcmd from "{txt}"')
                with open(txt, encoding="utf-8") as f:
                    self.write(f.read())

        return Command_txtcmd

    def isCommand(self, cmd):
        """
        Check if cmd (the argument of a command) is a command, too.
        """
        return True if cmd in self.commands else False

    def getCommand(self, cmd, paths):
        if not cmd.strip():
            return None
        path = None
        if cmd in self.commands:
            return self.commands[cmd]
        if cmd[0] in (".", "/"):
            path = self.fs.resolve_path(cmd, self.cwd)
            if not self.fs.exists(path):
                return None
        else:
            for i in [f"{self.fs.resolve_path(x, self.cwd)}/{cmd}" for x in paths]:
                if self.fs.exists(i):
                    path = i
                    break

        txt = os.path.normpath(
            "{}/txtcmds/{}".format(CowrieConfig.get("honeypot", "data_path"), path)
        )
        if os.path.exists(txt) and os.path.isfile(txt):
            return self.txtcmd(txt)

        if path in self.commands:
            return self.commands[path]

        log.msg(f"Can't find command {cmd}")
        return None

    def lineReceived(self, line: bytes) -> None:
        """
        IMPORTANT
        Before this, all data is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        string = line.decode("utf8")

        if self.cmdstack:
            self.cmdstack[-1].lineReceived(string)
        else:
            log.msg(f"discarding input {string}")
            stat = failure.Failure(error.ProcessDone(status=""))
            self.terminal.transport.processEnded(stat)

    def call_command(self, pp, cmd, *args):
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
        return r

    def eofReceived(self) -> None:
        # Shell received EOF, nicely exit
        """
        TODO: this should probably not go through transport, but use processprotocol to close stdin
        """
        ret = failure.Failure(error.ProcessTerminated(exitCode=0))
        self.terminal.transport.processEnded(ret)


class HoneyPotExecProtocol(HoneyPotBaseProtocol):
    # input_data is static buffer for stdin received from remote client
    input_data = b""

    def __init__(self, avatar, execcmd):
        """
        IMPORTANT
        Before this, execcmd is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        try:
            self.execcmd = execcmd.decode("utf8")
        except UnicodeDecodeError:
            log.err(f"Unusual execcmd: {execcmd!r}")

        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self) -> None:
        HoneyPotBaseProtocol.connectionMade(self)
        self.setTimeout(60)
        self.cmdstack = [honeypot.HoneyPotShell(self, interactive=False)]
        # TODO: quick and dirty fix to deal with \n separated commands
        # HoneypotShell() needs a rewrite to better work with pending input
        self.cmdstack[0].lineReceived("; ".join(self.execcmd.strip().split("\n")))

    def keystrokeReceived(self, keyID, modifier):
        self.input_data += keyID


class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):
    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self) -> None:
        self.displayMOTD()

        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)

        self.cmdstack = [honeypot.HoneyPotShell(self)]

        self.keyHandlers.update(
            {
                b"\x01": self.handle_HOME,  # CTRL-A
                b"\x02": self.handle_LEFT,  # CTRL-B
                b"\x03": self.handle_CTRL_C,  # CTRL-C
                b"\x04": self.handle_CTRL_D,  # CTRL-D
                b"\x05": self.handle_END,  # CTRL-E
                b"\x06": self.handle_RIGHT,  # CTRL-F
                b"\x08": self.handle_BACKSPACE,  # CTRL-H
                b"\x09": self.handle_TAB,
                b"\x0b": self.handle_CTRL_K,  # CTRL-K
                b"\x0c": self.handle_CTRL_L,  # CTRL-L
                b"\x0e": self.handle_DOWN,  # CTRL-N
                b"\x10": self.handle_UP,  # CTRL-P
                b"\x15": self.handle_CTRL_U,  # CTRL-U
                b"\x16": self.handle_CTRL_V,  # CTRL-V
                b"\x1b": self.handle_ESC,  # ESC
            }
        )

    def displayMOTD(self) -> None:
        try:
            self.terminal.write(self.fs.file_contents("/etc/motd"))
        except Exception:
            pass

    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        assert self.terminal is not None
        self.terminal.write(b"timed out waiting for input: auto-logout\n")
        HoneyPotBaseProtocol.timeoutConnection(self)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)
        self.keyHandlers = {}

    def initializeScreen(self) -> None:
        """
        Overriding super to prevent terminal.reset()
        """
        self.setInsertMode()

    def call_command(self, pp, cmd, *args):
        self.pp = pp
        self.setTypeoverMode()
        HoneyPotBaseProtocol.call_command(self, pp, cmd, *args)

    def characterReceived(self, ch, moreCharactersComing):
        """
        Easier way to implement password input?
        """
        self.resetTimeout()  # Reset the idle timeout
        if self.mode == "insert":
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex : self.lineBufferIndex + 1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input:
            assert self.terminal is not None
            self.terminal.write(ch)

    def handle_RETURN(self) -> None:
        if len(self.cmdstack) == 1:
            if self.lineBuffer:
                self.historyLines.append(b"".join(self.lineBuffer))
            self.historyPosition = len(self.historyLines)
        recvline.RecvLine.handle_RETURN(self)

    def handle_CTRL_C(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_CTRL_C()

    def handle_CTRL_D(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_CTRL_D()

    def handle_TAB(self) -> None:
        if self.cmdstack:
            self.cmdstack[-1].handle_TAB()

    def handle_CTRL_K(self) -> None:
        assert self.terminal is not None
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0 : self.lineBufferIndex]

    def handle_CTRL_L(self) -> None:
        """
        Handle a 'form feed' byte - generally used to request a screen
        refresh/redraw.
        """
        assert self.terminal is not None
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()

    def handle_CTRL_U(self) -> None:
        assert self.terminal is not None
        for _ in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex :]
        self.lineBufferIndex = 0

    def handle_CTRL_V(self) -> None:
        pass

    def handle_ESC(self) -> None:
        pass


class HoneyPotInteractiveTelnetProtocol(HoneyPotInteractiveProtocol):
    """
    Specialized HoneyPotInteractiveProtocol that provides Telnet specific
    overrides.
    """

    def __init__(self, avatar):
        HoneyPotInteractiveProtocol.__init__(self, avatar)

    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need to override how we grab
        the proper transport to access underlying Telnet information.
        """
        return self.terminal.transport.session.transport
