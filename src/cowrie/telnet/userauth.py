# Copyright (C) 2015, 2016 GoSecure Inc.
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import annotations


import struct

from twisted.conch.telnet import (
    ECHO,
    LINEMODE,
    NAWS,
    SGA,
    AuthenticatingTelnetProtocol,
    ITelnetProtocol,
)
from twisted.internet.protocol import connectionDone
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig
from cowrie.core.credentials import UsernamePasswordIP

# NEW-ENVIRON telnet option (RFC 1572)
# Used for environment variable exchange and targeted by CVE-2026-24061
NEW_ENVIRON = bytes([39])  # 0x27

# NEW-ENVIRON subnegotiation command bytes
NEW_ENVIRON_IS = 0  # Sender is supplying value
NEW_ENVIRON_SEND = 1  # Sender requests receiver send value
NEW_ENVIRON_INFO = 2  # Sender is supplying updated value

# NEW-ENVIRON variable type bytes
NEW_ENVIRON_VAR = 0  # Well-known variable name follows
NEW_ENVIRON_VALUE = 1  # Variable value follows
NEW_ENVIRON_ESC = 2  # Escape byte for literal VAR/VALUE/USERVAR bytes in data
NEW_ENVIRON_USERVAR = 3  # User-defined variable name follows


class HoneyPotTelnetAuthProtocol(AuthenticatingTelnetProtocol):
    """
    TelnetAuthProtocol that takes care of Authentication. Once authenticated this
    protocol is replaced with HoneyPotTelnetSession.
    """

    loginPrompt = b"login: "
    passwordPrompt = b"Password: "
    windowSize: list[int]

    def connectionMade(self):
        # self.transport.negotiationMap[NAWS] = self.telnet_NAWS
        # Initial option negotation. Want something at least for Mirai
        # for opt in (NAWS,):
        #    self.transport.doChain(opt).addErrback(log.err)

        # Register NEW-ENVIRON subnegotiation handler for CVE-2026-24061 detection
        self.transport.negotiationMap[NEW_ENVIRON] = self.telnet_NEW_ENVIRON

        # Store received environment variables
        self.environ_received: dict[str, str] = {}

        # I need to doubly escape here since my underlying
        # CowrieTelnetTransport hack would remove it and leave just \n
        self.windowSize = [40, 80]
        self.transport.write(self.factory.banner.replace(b"\n", b"\r\r\n"))
        self.transport.write(self.loginPrompt)

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        """
        Fires on pre-authentication disconnects
        """
        AuthenticatingTelnetProtocol.connectionLost(self, reason)

    def telnet_User(self, line):
        """
        Overridden to conditionally kill 'WILL ECHO' which confuses clients
        that don't implement a proper Telnet protocol (most malware)
        """
        self.username = line  # .decode()
        # only send ECHO option if we are chatting with a real Telnet client
        self.transport.willChain(ECHO)
        # FIXME: this should be configurable or provided via filesystem
        self.transport.write(self.passwordPrompt)
        return "Password"

    def telnet_Password(self, line):
        username, password = self.username, line  # .decode()
        del self.username

        def login(ignored):
            self.src_ip = self.transport.getPeer().host
            creds = UsernamePasswordIP(username, password, self.src_ip)
            d = self.portal.login(creds, self.src_ip, ITelnetProtocol)
            d.addCallback(self._cbLogin)
            d.addErrback(self._ebLogin)

        # are we dealing with a real Telnet client?
        if self.transport.options:
            # stop ECHO
            # even if ECHO negotiation fails we still want to attempt a login
            # this allows us to support dumb clients which is common in malware
            # thus the addBoth: on success and on exception (AlreadyNegotiating)
            self.transport.wontChain(ECHO).addBoth(login)
        else:
            # process login
            login("")

        return "Discard"

    def telnet_Command(self, command):
        self.transport.protocol.dataReceived(command + b"\r")
        return "Command"

    def _cbLogin(self, ial):
        """
        Fired on a successful login
        """
        _interface, protocol, logout = ial
        protocol.windowSize = self.windowSize
        self.protocol = protocol
        self.logout = logout
        self.state = "Command"

        self.transport.write(b"\n")

        # Remove the short timeout of the login prompt.
        self.transport.setTimeout(
            CowrieConfig.getint("honeypot", "idle_timeout", fallback=300)
        )

        # replace myself with avatar protocol
        protocol.makeConnection(self.transport)
        self.transport.protocol = protocol

    def _ebLogin(self, failure):
        # TODO: provide a way to have user configurable strings for wrong password
        self.transport.wontChain(ECHO)
        self.transport.write(b"\nLogin incorrect\n")
        self.transport.write(self.loginPrompt)
        self.state = "User"

    def telnet_NAWS(self, data):
        """
        From TelnetBootstrapProtocol in twisted/conch/telnet.py
        """
        if len(data) == 4:
            width, height = struct.unpack("!HH", b"".join(data))
            self.windowSize = [height, width]
        else:
            log.msg("Wrong number of NAWS bytes")

    def telnet_NEW_ENVIRON(self, data: list[bytes]) -> None:
        """
        Handle NEW-ENVIRON (RFC 1572) subnegotiation.

        Parses environment variables sent by the client and logs them.
        Also detects CVE-2026-24061 exploit attempts where USER=-f root
        is used to bypass authentication in vulnerable telnetd implementations.

        Subnegotiation format:
            IS/SEND/INFO [VAR name VALUE value]* [USERVAR name VALUE value]*
        """
        if not data:
            return

        # Join the data bytes
        raw_data = b"".join(data)
        if len(raw_data) < 1:
            return

        command = raw_data[0]

        # We only care about IS (0) and INFO (2) - client sending values
        if command not in (NEW_ENVIRON_IS, NEW_ENVIRON_INFO):
            return

        # Parse the environment variables
        env_vars = self._parse_new_environ_data(raw_data[1:])

        # Log each environment variable
        for name, value in env_vars.items():
            # Store for potential later use
            self.environ_received[name] = value

            # Log the environment variable (matches SSH cowrie.client.var pattern)
            log.msg(
                eventid="cowrie.client.var",
                format="Telnet NEW-ENVIRON: %(name)s=%(value)s",
                name=name,
                value=value,
            )

            # CVE-2026-24061 detection: USER environment variable with -f flag
            # This exploit bypasses authentication in GNU inetutils telnetd <= 2.7
            if name.upper() == "USER" and value.startswith("-f"):
                log.msg(
                    eventid="cowrie.telnet.exploit_attempt",
                    format="CVE-2026-24061 exploit attempt detected: USER=%(value)s",
                    cve="CVE-2026-24061",
                    name=name,
                    value=value,
                )

    def _parse_new_environ_data(self, data: bytes) -> dict[str, str]:
        """
        Parse NEW-ENVIRON subnegotiation data into a dictionary.

        Format: [VAR|USERVAR name VALUE value]* with ESC for escaping.
        """
        env_vars: dict[str, str] = {}
        if not data:
            return env_vars

        i = 0
        current_name: list[int] = []
        current_value: list[int] = []
        in_value = False
        escape_next = False

        while i < len(data):
            byte = data[i]

            if escape_next:
                # Previous byte was ESC, treat this byte as literal
                if in_value:
                    current_value.append(byte)
                else:
                    current_name.append(byte)
                escape_next = False
            elif byte == NEW_ENVIRON_ESC:
                # Next byte is escaped
                escape_next = True
            elif byte == NEW_ENVIRON_VAR or byte == NEW_ENVIRON_USERVAR:
                # Save previous variable if any
                if current_name:
                    name = bytes(current_name).decode("utf-8", errors="replace")
                    value = bytes(current_value).decode("utf-8", errors="replace")
                    env_vars[name] = value
                # Start new variable
                current_name = []
                current_value = []
                in_value = False
            elif byte == NEW_ENVIRON_VALUE:
                # Switch from name to value
                in_value = True
            else:
                # Regular data byte
                if in_value:
                    current_value.append(byte)
                else:
                    current_name.append(byte)

            i += 1

        # Don't forget the last variable
        if current_name:
            name = bytes(current_name).decode("utf-8", errors="replace")
            value = bytes(current_value).decode("utf-8", errors="replace")
            env_vars[name] = value

        return env_vars

    def enableLocal(self, option: bytes) -> bool:
        if option == ECHO:
            return True
        # TODO: check if twisted now supports SGA (see git commit c58056b0)
        elif option == SGA:
            return False
        else:
            return False

    def enableRemote(self, option: bytes) -> bool:
        # TODO: check if twisted now supports LINEMODE (see git commit c58056b0)
        if option == LINEMODE:
            return False
        elif option == NAWS:
            return True
        elif option == SGA:
            return True
        elif option == NEW_ENVIRON:
            # Accept NEW-ENVIRON to capture environment variables
            # This enables detection of CVE-2026-24061 exploit attempts
            return True
        else:
            return False
