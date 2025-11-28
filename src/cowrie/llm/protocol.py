# Copyright (c) 2024 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

from __future__ import annotations

import re
import socket
import time

from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.internet import error
from twisted.protocols.policies import TimeoutMixin
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig


def strip_markdown(text: str) -> str:
    """
    Remove markdown code block formatting from LLM responses.
    """
    # Remove ```language\n...\n``` blocks, keeping the content
    text = re.sub(r"```\w*\n?", "", text)
    # Remove any remaining backticks
    text = text.replace("`", "")
    return text.strip()


class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    Base protocol for interactive and non-interactive use
    """

    def __init__(self, avatar):
        self.user = avatar
        self.environ = avatar.environ
        self.hostname: str = self.user.server.hostname
        self.pp = None
        self.logintime: float
        self.realClientIP: str
        self.realClientPort: int
        self.kippoIP: str
        self.clientIP: str
        self.sessionno: int
        self.factory = None
        self.cwd = "/"
        self.data = None
        self.password_input = False

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

        timeout = CowrieConfig.getint("honeypot", "interactive_timeout", fallback=180)
        self.setTimeout(timeout)

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

    def connectionLost(self, reason):
        """
        Called when the connection is shut down.
        Clear any circular references here, and any external references to
        this Protocol. The connection has been closed.
        """
        self.setTimeout(None)
        insults.TerminalProtocol.connectionLost(self, reason)
        self.terminal = None  # (this should be done by super above)
        self.pp = None
        self.user = None
        self.environ = None

    def lineReceived(self, line: bytes) -> None:
        """
        IMPORTANT
        Before this, all data is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        string = line.decode("utf8")

        log.msg(eventid="cowrie.command.input", input=string, format="CMD: %(input)s")

        # Use LLM client to get a response
        self._process_command_with_llm(string)

    def _process_command_with_llm(self, command: str) -> None:
        """
        Process a command by sending it to the LLM and writing the response
        to the terminal.
        """
        from cowrie.llm.llm import LLMClient

        # Initialize LLM client if needed
        if not hasattr(self, "llm_client"):
            self.llm_client = LLMClient()
            self.command_history = []

        # Add the command to our history
        self.command_history.append(f"User: {command}")

        # Construct an appropriate prompt for the LLM
        # We'll include system context to help the LLM respond appropriately
        system_context = (
            "You are simulating a Linux server that has been accessed via SSH. "
            "Respond as if you were the shell on this system. "
            "Your response should be the output that would be displayed after executing the command. "
            "Keep responses realistic, including appropriate error messages for invalid commands. "
            "For file paths, maintain consistent state with previous commands. "
            f"The hostname is '{self.hostname}' and username is '{self.user.username}'. "
            f"The current working directory is '{self.cwd}'. "
        )

        prompt = [system_context] + self.command_history[
            -10:
        ]  # Keep only the last 10 commands for context

        # Get response asynchronously
        d = self.llm_client.get_response(prompt)
        d.addCallback(self._handle_llm_response)
        d.addErrback(self._handle_llm_error)

    def _handle_llm_response(self, response: str) -> None:
        """
        Handle the response from the LLM and display it to the user.
        """
        if self.terminal is None:
            return

        if response:
            clean_response = strip_markdown(response)
            self.command_history.append(f"System: {clean_response}")
            self.terminal.write(f"{clean_response}\n".encode())
        # If no response, just show the prompt silently (like an empty command)

        self._show_prompt()

    def _handle_llm_error(self, failure):
        """
        Handle errors from the LLM client.
        """
        log.err(f"LLM error: {failure}")
        if self.terminal is None:
            return
        # Show nothing - just the prompt, as if the command produced no output
        self._show_prompt()

    def _show_prompt(self):
        """
        Display the appropriate command prompt to the user.
        """
        # Build a realistic prompt
        if self.user.username == "root":
            prompt = f"{self.user.username}@{self.hostname}:{self.cwd}# "
        else:
            prompt = f"{self.user.username}@{self.hostname}:{self.cwd}$ "

        self.terminal.write(prompt.encode("utf-8"))

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

        # Process the exec command with LLM
        self._process_exec_with_llm()

    def _process_exec_with_llm(self) -> None:
        """
        Process an exec command with the LLM and return the result.
        Used when commands are passed directly to SSH (e.g., ssh user@host 'command')
        """
        from cowrie.llm.llm import LLMClient

        self.llm_client = LLMClient()
        self.command_history = []

        # Construct the prompt
        system_context = (
            "You are simulating a Linux server that has been accessed via SSH with a command to execute. "
            "Respond with ONLY the output that would be displayed after executing this command. "
            "Keep responses realistic, including appropriate error messages for invalid commands. "
            f"The hostname is '{self.hostname}' and username is '{self.user.username}'. "
            f"The current working directory is '{self.cwd}'. "
            "The command to execute is: " + self.execcmd
        )

        prompt = [system_context]

        # Get response asynchronously
        d = self.llm_client.get_response(prompt)
        d.addCallback(self._handle_exec_response)
        d.addErrback(self._handle_exec_error)

    def _handle_exec_response(self, response: str) -> None:
        """
        Handle the LLM response for an exec command.
        """
        if self.terminal is None:
            return

        if response:
            clean_response = strip_markdown(response)
            self.terminal.write(f"{clean_response}\n".encode())
        # If no response, produce no output (some commands are silent)

        ret = failure.Failure(error.ProcessTerminated(exitCode=0))
        self.terminal.transport.processEnded(ret)

    def _handle_exec_error(self, exec_failure):
        """
        Handle errors from the LLM client during exec.
        """
        log.err(f"LLM exec error: {exec_failure}")
        if self.terminal is None:
            return

        # Produce no output, exit with 0 (as if command succeeded silently)
        ret = failure.Failure(error.ProcessTerminated(exitCode=0))
        self.terminal.transport.processEnded(ret)

    def keystrokeReceived(self, keyID, modifier):
        self.input_data += keyID


class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):
    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, avatar)

    def connectionMade(self) -> None:
        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)

        from cowrie.llm.llm import LLMClient

        self.llm_client = LLMClient()
        self.command_history = []

        # Show welcome banner
        welcome = f"Welcome to {self.hostname}\n"
        self.terminal.write(welcome.encode("utf-8"))

        self._show_prompt()

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

    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        assert self.terminal is not None
        self.terminal.write(b"timed out waiting for input: auto-logout\n")
        HoneyPotBaseProtocol.timeoutConnection(self)

    def connectionLost(self, reason):
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)
        self.keyHandlers = {}

    def initializeScreen(self) -> None:
        """
        Overriding super to prevent terminal.reset()
        """
        self.setInsertMode()

    def characterReceived(self, ch, moreCharactersComing):
        if self.terminal is None:
            return
        if self.mode == "insert":
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex : self.lineBufferIndex + 1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input:
            self.terminal.write(ch)

    def handle_RETURN(self) -> None:
        if self.lineBuffer:
            self.historyLines.append(b"".join(self.lineBuffer))
        self.historyPosition = len(self.historyLines)
        recvline.RecvLine.handle_RETURN(self)

    def handle_CTRL_C(self) -> None:
        pass

    def handle_CTRL_D(self) -> None:
        if self.terminal is not None:
            self.terminal.loseConnection()

    def handle_TAB(self) -> None:
        pass

    def handle_CTRL_K(self) -> None:
        if self.terminal is None:
            return
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0 : self.lineBufferIndex]

    def handle_CTRL_L(self) -> None:
        """
        Handle a 'form feed' byte - generally used to request a screen
        refresh/redraw.
        """
        if self.terminal is None:
            return
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()

    def handle_CTRL_U(self) -> None:
        if self.terminal is None:
            return
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
