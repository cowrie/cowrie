from __future__ import annotations
import os
import re
import time

from twisted.python import log

from cowrie.core import ttylog
from cowrie.core.checkers import HoneypotPasswordChecker
from cowrie.core.config import CowrieConfig


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


class TelnetHandler:
    def __init__(self, server):
        # holds packet data; useful to manipulate it across functions as needed
        self.currentData: bytes = b""
        self.sendData = True

        # front and backend references
        self.server = server
        self.client = None

        # definitions from config
        self.spoofAuthenticationData = CowrieConfig.getboolean(
            "proxy", "telnet_spoof_authentication"
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
        self.authStarted = False
        self.authDone = False

        self.usernameState = b""  # TODO clear on end
        self.inputingLogin = False

        self.passwordState = b""  # TODO clear on end
        self.inputingPassword = False

        self.waitingLoginEcho = False

        # some data is sent by the backend right before the password prompt, we want to capture that
        # and the respective frontend response and send it before starting to intercept auth data
        self.prePasswordData = False

        # buffer
        self.backend_buffer = []

        # tty logging
        self.startTime = time.time()
        self.ttylogPath = CowrieConfig.get("honeypot", "ttylog_path")
        self.ttylogEnabled = CowrieConfig.getboolean(
            "honeypot", "ttylog", fallback=True
        )
        self.ttylogSize = 0

        if self.ttylogEnabled:
            self.ttylogFile = "{}/telnet-{}.log".format(
                self.ttylogPath, time.strftime("%Y%m%d-%H%M%S")
            )
            ttylog.ttylog_open(self.ttylogFile, self.startTime)

    def setClient(self, client):
        self.client = client

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

            log.msg(
                eventid="cowrie.log.closed",
                format="Closing TTY Log: %(ttylog)s after %(duration)d seconds",
                ttylog=shasumfile,
                size=self.ttylogSize,
                shasum=shasum,
                duplicate=duplicate,
                duration=time.time() - self.startTime,
            )

    def sendBackend(self, data: bytes) -> None:
        self.backend_buffer.append(data)

        if not self.client:
            return

        for packet in self.backend_buffer:
            self.client.transport.write(packet)
            # log raw packets if user sets so
            if CowrieConfig.getboolean("proxy", "log_raw", fallback=False):
                log.msg("to_backend - " + data.decode("unicode-escape"))

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

            self.backend_buffer = self.backend_buffer[1:]

    def sendFrontend(self, data: bytes) -> None:
        self.server.transport.write(data)

        # log raw packets if user sets so
        if CowrieConfig.getboolean("proxy", "log_raw", fallback=False):
            log.msg("to_frontend - " + data.decode("unicode-escape"))

        if self.ttylogEnabled and self.authStarted:
            ttylog.ttylog_write(
                self.ttylogFile, len(data), ttylog.TYPE_OUTPUT, time.time(), data
            )
            # self.ttylogSize += len(data)

    def addPacket(self, parent: str, data: bytes) -> None:
        self.currentData = data
        self.sendData = True

        if self.spoofAuthenticationData and not self.authDone:
            # detect prompts from backend
            if parent == "backend":
                self.setProcessingStateBackend()

            # detect patterns from frontend
            if parent == "frontend":
                self.setProcessingStateFrontend()

            # save user inputs from frontend
            if parent == "frontend":
                if self.inputingPassword:
                    self.processPasswordInput()

                if self.inputingLogin:
                    self.processUsernameInput()

            # capture username echo from backend
            if self.waitingLoginEcho and parent == "backend":
                self.currentData = self.currentData.replace(
                    self.backendLogin + b"\r\n", b""
                )
                self.waitingLoginEcho = False

        # log user commands
        if parent == "frontend" and self.authDone:
            self.currentCommand += data.replace(b"\r\x00", b"").replace(b"\r\n", b"")

            # check if a command has terminated
            if b"\r" in data:
                if len(self.currentCommand) > 0:
                    log.msg(
                        eventid="cowrie.command.input",
                        input=self.currentCommand,
                        format="CMD: %(input)s",
                    )
                self.currentCommand = b""

        # send data after processing (also check if processing did not reduce it to an empty string)
        if self.sendData and len(self.currentData):
            if parent == "frontend":
                self.sendBackend(self.currentData)
            else:
                self.sendFrontend(self.currentData)

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
            terminatingChar = chr(
                self.currentData[self.currentData.index(b"\r") + 1]
            ).encode()  # usually \n or \x00

            # cleanup
            self.usernameState = process_backspaces(self.usernameState)

            log.msg(f"User input login: {self.usernameState.decode('unicode-escape')}")
            self.inputingLogin = False

            # actually send to backend
            self.currentData = self.backendLogin + b"\r" + terminatingChar
            self.sendData = True

            # we now have to ignore the username echo from the backend in the next packet
            self.waitingLoginEcho = True

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
            terminatingChar = chr(
                self.currentData[self.currentData.index(b"\r") + 1]
            ).encode()  # usually \n or \x00

            # cleanup
            self.passwordState = process_backspaces(self.passwordState)

            log.msg(
                f"User input password: {self.passwordState.decode('unicode-escape')}"
            )
            self.inputingPassword = False

            # having the password (and the username, either empy or set before), we can check the login
            # on the database, and if valid authenticate or else, if invalid send a fake password to get
            # the login failed prompt
            src_ip = self.server.transport.getPeer().host
            if HoneypotPasswordChecker().checkUserPass(
                self.usernameState, self.passwordState, src_ip
            ):
                passwordToSend = self.backendPassword
                self.authDone = True
                self.server.setTimeout(
                    CowrieConfig.getint("honeypot", "interactive_timeout", fallback=300)
                )
            else:
                log.msg("Sending invalid auth to backend")
                passwordToSend = self.backendPassword + b"fake"

            # actually send to backend
            self.currentData = passwordToSend + b"\r" + terminatingChar
            self.sendData = True

    def setProcessingStateBackend(self) -> None:
        """
        This function analyses a data packet and sets the processing state of the handler accordingly.
        It looks for authentication phases (password input and username input), as well as data that
        may need to be processed specially.
        """
        hasPassword = re.search(self.passwordPromptRegex, self.currentData)
        if hasPassword:
            log.msg("Password prompt from backend")
            self.authStarted = True
            self.inputingPassword = True
            self.passwordState = b""

        hasLogin = re.search(self.usernamePromptRegex, self.currentData)
        if hasLogin:
            log.msg("Login prompt from backend")
            self.authStarted = True
            self.inputingLogin = True
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
            log.msg(
                f"Detected username {self.usernameState.decode('unicode-escape')} in negotiation, spoofing for backend..."
            )

            # spoof username in data sent
            # username is always sent correct, password is the one sent wrong if we don't want to authenticate
            self.currentData = negotiationLoginPattern.sub(
                rb"\1" + self.backendLogin + rb"\3", self.currentData
            )
