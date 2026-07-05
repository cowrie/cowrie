# SPDX-FileCopyrightText: 2016 Olivier Bilodeau <obilodeau@gosecure.ca>
# SPDX-FileCopyrightText: 2015, 2016 GoSecure Inc.
# SPDX-FileCopyrightText: 2016-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
"""
Telnet Transport and Authentication for the Honeypot

@author: Olivier Bilodeau <obilodeau@gosecure.ca>
"""

from __future__ import annotations

import time
import uuid

from twisted.conch.telnet import AlreadyNegotiating, TelnetTransport
from twisted.internet.protocol import connectionDone
from twisted.protocols.policies import TimeoutMixin
from twisted.python import failure, log

from cowrie.core.config import CowrieConfig
from cowrie.core.events import EventLog, transport_events

# Telnet option names for logging (RFC 854, RFC 855, RFC 1572, etc.)
TELNET_OPTIONS: dict[int, str] = {
    0: "BINARY",
    1: "ECHO",
    3: "SGA",
    5: "STATUS",
    6: "TIMING-MARK",
    24: "TERMINAL-TYPE",
    31: "NAWS",
    32: "TERMINAL-SPEED",
    33: "REMOTE-FLOW-CONTROL",
    34: "LINEMODE",
    35: "X-DISPLAY-LOCATION",
    36: "ENVIRON",
    39: "NEW-ENVIRON",
    255: "EXOPL",
}


class CowrieTelnetTransport(TelnetTransport, TimeoutMixin):
    """
    CowrieTelnetTransport
    """

    # The session's event emitter, bound in connectionMade when the running
    # application provides a dispatcher.
    events: EventLog | None = None

    # Set while the connection is being torn down. Telnet.connectionLost()
    # iterates self.options and errbacks pending negotiations; our retry
    # machinery must not re-enter negotiation during that iteration, since
    # that would mutate self.options mid-iteration and leak failed Deferreds.
    _closing: bool = False

    def connectionMade(self):
        self.transportId: str = uuid.uuid4().hex[:12]
        # (command, option_byte) pairs already logged, to suppress a scanner
        # flooding the same option negotiation (see _log_negotiation).
        self._logged_options: set[tuple[str, int]] = set()
        self.startTime = time.time()
        self.setTimeout(
            CowrieConfig.getint("honeypot", "authentication_timeout", fallback=120)
        )

        self.events = transport_events(
            self.factory,
            self.transport,
            session=self.transportId,
            protocol="telnet",
        )

        TelnetTransport.connectionMade(self)

    def write(self, data):
        """
        Because of the presence of two ProtocolTransportMixin in the protocol
        stack once authenticated, I need to override write() and remove a \r
        otherwise we end up with \r\r\n on the wire.

        It is kind of a hack. I asked for a better solution here:
        http://stackoverflow.com/questions/35087250/twisted-telnet-server-how-to-avoid-nested-crlf
        """
        self.transport.write(data.replace(b"\r\n", b"\n"))

    def dataReceived(self, data: bytes) -> None:
        """
        Twisted's Telnet.dataReceived() raises ValueError on an unrecognised
        byte following IAC (e.g. a scanner sending IAC 0x01 outside a WILL/DO
        envelope). Unhandled, that escapes into the reactor as an "Unhandled
        Error" and drops the transport without the normal connectionLost()
        cleanup. Catch it, log the protocol error, and lose the connection so
        the usual teardown runs.

        Telnet.dataReceived() also re-enters the application stack
        (applicationDataReceived -> protocol.dataReceived, negotiate,
        commandReceived), so a ValueError raised by downstream honeypot code is
        caught here too. Log the full traceback as well so a genuine bug is not
        silently reduced to a one-line protocol error.
        """
        try:
            TelnetTransport.dataReceived(self, data)
        except ValueError as e:
            if self.events:
                self.events.dispatch(
                    "cowrie.telnet.error",
                    "Telnet protocol error %(error)s; dropping connection",
                    error=str(e),
                )
            log.err()
            if self.transport:
                self.transport.loseConnection()

    def timeoutConnection(self) -> None:
        """
        Make sure all sessions time out eventually.
        Timeout is reset when authentication succeeds.
        """
        log.msg("Timeout reached in CowrieTelnetTransport")
        if self.transport:
            self.transport.loseConnection()

    def connectionLost(self, reason: failure.Failure = connectionDone) -> None:
        """
        Fires on pre-authentication disconnects
        """
        self._closing = True
        self.setTimeout(None)
        TelnetTransport.connectionLost(self, reason)
        duration_ms = round((time.time() - self.startTime) * 1000)
        if self.events is not None:
            self.events.session_closed(duration_ms)

    def willChain(self, option):
        return self._chainNegotiation(None, self.will, option)

    def wontChain(self, option):
        return self._chainNegotiation(None, self.wont, option)

    def doChain(self, option):
        return self._chainNegotiation(None, self.do, option)

    def dontChain(self, option):
        return self._chainNegotiation(None, self.dont, option)

    def _handleNegotiationError(self, f, func, option):
        # The connection is going away; Telnet.connectionLost() is iterating
        # self.options. Do not retry negotiation, which would mutate that dict.
        if self._closing:
            return
        if f.type is AlreadyNegotiating:
            s = self.getOptionState(option)
            # do/dont negotiate the remote side (him); will/wont negotiate ours (us).
            side = s.him if func in (self.do, self.dont) else s.us
            if side.onResult is not None:
                side.onResult.addCallback(self._chainNegotiation, func, option)
                side.onResult.addErrback(self._handleNegotiationError, func, option)
            else:
                # The pending negotiation cleared before we could chain onto it.
                # Retry once; func() returns a failed Deferred (e.g.
                # AlreadyNegotiating) when it still cannot proceed, so swallow
                # that rather than leaving it as an unhandled Deferred. Do not
                # chain back into _handleNegotiationError, which would recurse.
                func(option).addErrback(lambda _: None)
        # We only care about AlreadyNegotiating, everything else can be ignored
        # Possible other types include OptionRefused, AlreadyDisabled, AlreadyEnabled, ConnectionDone, ConnectionLost
        elif f.type is AssertionError:
            log.msg(
                "Client tried to illegally refuse to disable an option; ignoring, but undefined behavior may result"
            )
            # TODO: Is ignoring this violation of the protocol the proper behavior?
            # Should the connection be terminated instead?
            # The telnetd package on Ubuntu (netkit-telnet) does all negotiation before sending the login prompt,
            # but does handle client-initiated negotiation at any time.

    def _chainNegotiation(self, res, func, option):
        # See _handleNegotiationError: never re-drive negotiation during teardown.
        if self._closing:
            return None
        return func(option).addErrback(self._handleNegotiationError, func, option)

    def _get_option_name(self, option: bytes) -> str:
        """Get human-readable name for a telnet option byte."""
        if option:
            option_byte = option[0] if isinstance(option, bytes) else option
            return TELNET_OPTIONS.get(option_byte, f"UNKNOWN-{option_byte}")
        return "UNKNOWN"

    def _log_negotiation(self, command: str, option: bytes) -> None:
        """Log a telnet option negotiation once per (command, option) per
        connection.

        Logged for security monitoring and CVE detection. A scanner can blast
        the same negotiation (e.g. ``WONT NAWS``) hundreds of times; logging
        each one floods the log, so identical repeats within a connection are
        suppressed after the first.
        """
        option_byte = option[0] if option else 0
        key = (command, option_byte)
        if key in self._logged_options:
            return
        self._logged_options.add(key)
        if self.events:
            self.events.dispatch(
                "cowrie.telnet.option",
                f"Telnet {command} %(option_name)s",
                command=command,
                option_name=self._get_option_name(option),
                option_byte=option_byte,
            )

    def telnet_WILL(self, option: bytes) -> None:
        """Client indicates willingness to enable an option."""
        self._log_negotiation("WILL", option)
        TelnetTransport.telnet_WILL(self, option)

    def telnet_WONT(self, option: bytes) -> None:
        """Client refuses to enable an option."""
        self._log_negotiation("WONT", option)
        TelnetTransport.telnet_WONT(self, option)

    def telnet_DO(self, option: bytes) -> None:
        """Client requests that we enable an option."""
        self._log_negotiation("DO", option)
        TelnetTransport.telnet_DO(self, option)

    def telnet_DONT(self, option: bytes) -> None:
        """Client requests that we disable an option."""
        self._log_negotiation("DONT", option)
        TelnetTransport.telnet_DONT(self, option)
