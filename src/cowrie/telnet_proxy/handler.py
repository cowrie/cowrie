# SPDX-FileCopyrightText: 2019 Guilherme Borges <guilhermerosasborges@gmail.com>
# SPDX-FileCopyrightText: 2020-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Relays telnet traffic between attacker and backend for the proxy,
# ABOUTME: spotting the login exchange to log or replace the credentials.

from __future__ import annotations

import os
import re
import time
from enum import Enum, auto

from twisted.logger import Logger

from cowrie.core import ttylog
from cowrie.core.checkers import HoneypotPasswordChecker
from cowrie.core.config import CowrieConfig
from cowrie.core.pending import PendingQueue


def process_backspaces(s: bytes) -> bytes:
    """
    Takes a user-input string that might have backspaces in it (represented as 0x7F),
    and actually performs the 'backspace operation' to return a clean string.
    """
    n = b""
    for i in range(len(s)):
        char = chr(s[i]).encode()
        if char == b"\x7f":
            n = n[:-1]
        else:
            n += char
    return n


def remove_all(original_string: bytes, remove_list: list[bytes]) -> bytes:
    """
    Removes all substrings in the list remove_list from string original_string.
    """
    n = original_string
    for substring in remove_list:
        n = n.replace(substring, b"")
    return n


class LoginPhase(Enum):
    """Where the attacker is in the backend's login, as the proxy sees it."""

    BEFORE_LOGIN = auto()  # no login or password prompt seen yet
    USERNAME = auto()  # the attacker is typing a username
    USERNAME_SENT = auto()  # the backend's echo of its own username is still to come
    PASSWORD = auto()  # the attacker is typing a password
    AWAITING_PROMPT = auto()  # an answer was sent; waiting for the next prompt
    LOGGED_IN = auto()  # the honeypot accepted the credentials


class TelnetHandler:
    _log = Logger()

    def __init__(self, server):
        # holds packet data; useful to manipulate it across functions as needed
        self.currentData: bytes = b""
        self.sendData = True

        # front and backend references
        self.server = server
        self.client = None

        # definitions from config
        self.spoofAuthenticationData = CowrieConfig.getboolean(
            "proxy", "telnet_spoof_authentication", fallback=True
        )

        self.backendLogin = CowrieConfig.get("proxy", "backend_user").encode()
        self.backendPassword = CowrieConfig.get("proxy", "backend_pass").encode()

        self.usernameInNegotiationRegex = CowrieConfig.get(
            "proxy", "telnet_username_in_negotiation_regex", raw=True
        ).encode()
        self.usernamePromptRegex = CowrieConfig.get(
            "proxy", "telnet_username_prompt_regex", raw=True
        ).encode()
        self.passwordPromptRegex = CowrieConfig.get(
            "proxy", "telnet_password_prompt_regex", raw=True
        ).encode()

        # telnet state
        self.currentCommand = b""

        # auth state
        self.phase = LoginPhase.BEFORE_LOGIN
        self.usernameState = b""  # TODO clear on end
        self.passwordState = b""  # TODO clear on end

        # some data is sent by the backend right before the password prompt, we want to capture that
        # and the respective frontend response and send it before starting to intercept auth data
        self.prePasswordData = False

        # frontend data held until the backend connects
        self.to_backend: PendingQueue[bytes] = PendingQueue(self._write_backend)

        # tty logging
        self.startTime = time.time()
        self.ttylogPath = CowrieConfig.get("honeypot", "ttylog_path", fallback=".")
        self.ttylogEnabled = CowrieConfig.getboolean(
            "honeypot", "ttylog", fallback=True
        )
        self.ttylogSize = 0

        if self.ttylogEnabled:
            self.ttylogFile = "{}/telnet-{}.log".format(
                self.ttylogPath, time.strftime("%Y%m%d-%H%M%S")
            )
            ttylog.ttylog_open(self.ttylogFile, self.startTime)

    @property
    def authStarted(self) -> bool:
        """Whether the backend has shown a login prompt yet."""
        return self.phase is not LoginPhase.BEFORE_LOGIN

    @property
    def authDone(self) -> bool:
        """Whether the attacker has logged in."""
        return self.phase is LoginPhase.LOGGED_IN

    def setClient(self, client):
        self.client = client
        self.to_backend.release()

    def close(self):
        if self.ttylogEnabled:
            ttylog.ttylog_close(self.ttylogFile, time.time())
            shasum = ttylog.ttylog_inputhash(self.ttylogFile)
            shasumfile = os.path.join(self.ttylogPath, shasum)

            if os.path.exists(shasumfile):
                duplicate = True
                os.remove(self.ttylogFile)
            else:
                duplicate = False
                os.rename(self.ttylogFile, shasumfile)
                umask = os.umask(0)
                os.umask(umask)
                os.chmod(shasumfile, 0o666 & ~umask)

            self.ttylogEnabled = (
                False  # do not close again if function called after closing
            )

            if self.server.events:
                self.server.events.dispatch(
                    "cowrie.log.closed",
                    "Closing TTY Log: %(ttylog)s after %(duration_ms)d milliseconds",
                    ttylog=shasumfile,
                    size=self.ttylogSize,
                    shasum=shasum,
                    duplicate=duplicate,
                    duration_ms=round((time.time() - self.startTime) * 1000),
                )

    def sendBackend(self, data: bytes) -> None:
        self.to_backend.put(data)

    def _write_backend(self, data: bytes) -> None:
        self.client.transport.write(data)
        # log raw packets if user sets so
        if CowrieConfig.getboolean("proxy", "log_raw", fallback=False):
            self._log.info("to_backend - {data}", data=data.decode("unicode-escape"))

        if self.ttylogEnabled and self.authStarted:
            cleanData = data.replace(
                b"\x00", b"\n"
            )  # some frontends send 0xFF instead of newline
            ttylog.ttylog_write(
                self.ttylogFile,
                len(cleanData),
                ttylog.TYPE_INPUT,
                time.time(),
                cleanData,
            )
            self.ttylogSize += len(cleanData)

    def sendFrontend(self, data: bytes) -> None:
        self.server.transport.write(data)

        # log raw packets if user sets so
        if CowrieConfig.getboolean("proxy", "log_raw", fallback=False):
            self._log.info("to_frontend - {data}", data=data.decode("unicode-escape"))

        if self.ttylogEnabled and self.authStarted:
            ttylog.ttylog_write(
                self.ttylogFile, len(data), ttylog.TYPE_OUTPUT, time.time(), data
            )
            # self.ttylogSize += len(data)

    def addPacket(self, parent: str, data: bytes) -> None:
        self.currentData = data
        self.sendData = True
        # The packet that completes the login is the password, not a command.
        was_logged_in = self.authDone

        if self.spoofAuthenticationData and not self.authDone:
            if parent == "backend":
                self.setProcessingStateBackend()
            else:
                self.setProcessingStateFrontend()
                if self.phase is LoginPhase.PASSWORD:
                    self.processPasswordInput()
                elif self.phase is LoginPhase.USERNAME:
                    self.processUsernameInput()

        # log user commands
        if parent == "frontend" and was_logged_in:
            self.currentCommand += data.replace(b"\r\x00", b"").replace(b"\r\n", b"")

            # check if a command has terminated
            if b"\r" in data:
                if len(self.currentCommand) > 0 and self.server.events:
                    self.server.events.dispatch(
                        "cowrie.command.input",
                        "CMD: %(input)s",
                        input=self.currentCommand,
                    )
                self.currentCommand = b""

        # send data after processing (also check if processing did not reduce it to an empty string)
        if self.sendData and len(self.currentData):
            if parent == "frontend":
                self.sendBackend(self.currentData)
            else:
                self.sendFrontend(self.currentData)

    def terminating_char(self) -> bytes:
        """The byte the client sent after its CR, usually \\n or NUL.

        There need not be one: a client may send a bare CR for Enter, or the
        CR and its companion may land in separate reads. An empty result
        forwards the bare CR to the backend as the client sent it.
        """
        after = self.currentData.index(b"\r") + 1
        return self.currentData[after : after + 1]

    def processUsernameInput(self) -> None:
        self.sendData = False  # withold data until input is complete

        # remove control characters
        control_chars = [b"\r", b"\x00", b"\n"]
        self.usernameState += remove_all(self.currentData, control_chars)

        # backend echoes data back to user to show on terminal prompt
        #     - NULL char is replaced by NEWLINE by backend
        #     - 0x7F (backspace) is replaced by two 0x08 separated by a blankspace
        self.sendFrontend(
            self.currentData.replace(b"\x7f", b"\x08 \x08").replace(b"\x00", b"\n")
        )

        # check if done inputing
        if b"\r" in self.currentData:
            terminatingChar = self.terminating_char()

            # cleanup
            self.usernameState = process_backspaces(self.usernameState)

            self._log.info(
                "User input login: {username}",
                username=self.usernameState.decode("unicode-escape"),
            )
            # actually send to backend
            self.currentData = self.backendLogin + b"\r" + terminatingChar
            self.sendData = True

            # we now have to ignore the username echo from the backend in the next packet
            self.phase = LoginPhase.USERNAME_SENT

    def processPasswordInput(self) -> None:
        self.sendData = False  # withold data until input is complete

        if self.prePasswordData:
            self.sendBackend(self.currentData[:3])
            self.prePasswordData = False

        # remove control characters
        control_chars = [b"\xff", b"\xfd", b"\x01", b"\r", b"\x00", b"\n"]
        self.passwordState += remove_all(self.currentData, control_chars)

        # check if done inputing
        if b"\r" in self.currentData:
            terminatingChar = self.terminating_char()

            # cleanup
            self.passwordState = process_backspaces(self.passwordState)

            self._log.info(
                "User input password: {password}",
                password=self.passwordState.decode("unicode-escape"),
            )
            # having the password (and the username, either empy or set before), we can check the login
            # on the database, and if valid authenticate or else, if invalid send a fake password to get
            # the login failed prompt
            src_ip = self.server.transport.getPeer().host
            if HoneypotPasswordChecker().checkUserPass(
                self.usernameState, self.passwordState, src_ip, self.server.events
            ):
                passwordToSend = self.backendPassword
                self.phase = LoginPhase.LOGGED_IN
                self.server.setTimeout(
                    CowrieConfig.getint("honeypot", "idle_timeout", fallback=300)
                )
            else:
                self._log.info("Sending invalid auth to backend")
                passwordToSend = self.backendPassword + b"fake"
                self.phase = LoginPhase.AWAITING_PROMPT

            # actually send to backend
            self.currentData = passwordToSend + b"\r" + terminatingChar
            self.sendData = True

    def setProcessingStateBackend(self) -> None:
        """
        This function analyses a data packet and sets the processing state of the handler accordingly.
        It looks for authentication phases (password input and username input), as well as data that
        may need to be processed specially.
        """
        if self.phase is LoginPhase.USERNAME_SENT:
            # the first backend packet after the username echoes it back
            self.currentData = self.currentData.replace(
                self.backendLogin + b"\r\n", b""
            )
            self.phase = LoginPhase.AWAITING_PROMPT

        hasPassword = re.search(self.passwordPromptRegex, self.currentData)
        if hasPassword:
            self._log.info("Password prompt from backend")
            self.phase = LoginPhase.PASSWORD
            self.passwordState = b""

        hasLogin = re.search(self.usernamePromptRegex, self.currentData)
        if hasLogin:
            self._log.info("Login prompt from backend")
            self.phase = LoginPhase.USERNAME
            self.usernameState = b""

        self.prePasswordData = b"\xff\xfb\x01" in self.currentData

    def setProcessingStateFrontend(self) -> None:
        """
        Same for the frontend.
        """
        # login username is sent in channel negotiation to match the client's username
        negotiationLoginPattern = re.compile(self.usernameInNegotiationRegex)
        hasNegotiationLogin = negotiationLoginPattern.search(self.currentData)
        if hasNegotiationLogin:
            self.usernameState = hasNegotiationLogin.group(2)
            username_str = self.usernameState.decode("unicode-escape")
            self._log.info(
                "Detected username {username} in negotiation, spoofing for backend...",
                username=username_str,
            )

            # Log the environment variable for consistency with shell mode
            if self.server.events:
                self.server.events.dispatch(
                    "cowrie.client.var",
                    "Telnet NEW-ENVIRON: %(name)s=%(value)s",
                    name="USER",
                    value=username_str,
                )

            # CVE-2026-24061 detection: USER environment variable with -f flag
            # This exploit bypasses authentication in GNU inetutils telnetd <= 2.7
            if username_str.startswith("-f") and self.server.events:
                self.server.events.dispatch(
                    "cowrie.telnet.exploit_attempt",
                    "CVE-2026-24061 exploit attempt detected: USER=%(value)s",
                    cve="CVE-2026-24061",
                    name="USER",
                    value=username_str,
                )

            # spoof username in data sent
            # username is always sent correct, password is the one sent wrong if we don't want to authenticate
            self.currentData = negotiationLoginPattern.sub(
                rb"\1" + self.backendLogin + rb"\3", self.currentData
            )
