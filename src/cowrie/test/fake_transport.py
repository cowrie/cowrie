# Copyright (c) 2016 Dave Germiquet
# See LICENSE for details.

from __future__ import annotations

from typing import ClassVar, TYPE_CHECKING


from twisted.conch.insults import insults
from twisted.test import proto_helpers

if TYPE_CHECKING:
    from collections.abc import Callable

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, N_COLORS = list(range(9))


class Container:
    """This class is placeholder for creating a fake interface.

    @var host Client fake information
    @var port Fake Port for connection
    @var otherVersionString version
    """

    otherVersionString = "1.0"
    transportId = "test-suite"
    id = "test-suite"
    sessionno = 1
    starttime = 0
    session: Container | None
    sessions: ClassVar[dict[int, str]] = {}
    conn: Container | None
    transport: Container | None
    factory: Container | None

    def getPeer(self):
        """Fake function for mockup."""
        self.host = "1.1.1.1"
        self.port = 2222
        return self

    def processEnded(self, reason):
        """Fake function for mockup."""
        pass


class FakeTransport(proto_helpers.StringTransport):
    """Fake transport with abortConnection() method."""

    # Thanks to TerminalBuffer (some code was taken from twisted Terminal Buffer)

    redirFiles: ClassVar[set[list[str]]] = set()
    width = 80
    height = 24
    void = object()

    for keyID in (
        "UP_ARROW",
        "DOWN_ARROW",
        "RIGHT_ARROW",
        "LEFT_ARROW",
        "HOME",
        "INSERT",
        "DELETE",
        "END",
        "PGUP",
        "PGDN",
        "F1",
        "F2",
        "F3",
        "F4",
        "F5",
        "F6",
        "F7",
        "F8",
        "F9",
        "F10",
        "F11",
        "F12",
    ):
        exec(f"{keyID} = object()")

    TAB = "\x09"
    BACKSPACE = "\x08"

    modes: ClassVar[dict[str, Callable]] = {}

    # '\x01':     self.handle_HOME,	# CTRL-A
    # '\x02':     self.handle_LEFT,	# CTRL-B
    # '\x03':     self.handle_CTRL_C,	# CTRL-C
    # '\x04':     self.handle_CTRL_D,	# CTRL-D
    # '\x05':     self.handle_END,	# CTRL-E
    # '\x06':     self.handle_RIGHT,	# CTRL-F
    # '\x08':     self.handle_BACKSPACE,	# CTRL-H
    # '\x09':     self.handle_TAB,
    # '\x0B':     self.handle_CTRL_K,	# CTRL-K
    # '\x0C':     self.handle_CTRL_L,	# CTRL-L
    # '\x0E':     self.handle_DOWN,	# CTRL-N
    # '\x10':     self.handle_UP,		# CTRL-P
    # '\x15':     self.handle_CTRL_U,	# CTRL-U

    def setModes(self, modes):
        for m in modes:
            self.modes[m] = True

    aborting = False

    def abortConnection(self):
        self.aborting = True

    def resetModes(self, modes):
        for m in modes:
            try:
                del self.modes[m]
            except KeyError:
                pass

    def setPrivateModes(self, modes):
        """Enable the given modes.

        Track which modes have been enabled so that the implementations of
        other L{insults.ITerminalTransport} methods can be properly implemented
        to respect these settings.

        @see: L{resetPrivateModes}
        @see: L{insults.ITerminalTransport.setPrivateModes}
        """
        for m in modes:
            self.privateModes[m] = True

    def reset(self):
        self.home = insults.Vector(0, 0)
        self.x = self.y = 0
        self.modes = {}
        self.privateModes = {}
        self.setPrivateModes(
            [insults.privateModes.AUTO_WRAP, insults.privateModes.CURSOR_MODE]
        )
        self.numericKeypad = "app"
        self.activeCharset = insults.G0
        self.graphicRendition = {
            "bold": False,
            "underline": False,
            "blink": False,
            "reverseVideo": False,
            "foreground": WHITE,
            "background": BLACK,
        }
        self.charsets = {
            insults.G0: insults.CS_US,
            insults.G1: insults.CS_US,
            insults.G2: insults.CS_ALTERNATE,
            insults.G3: insults.CS_ALTERNATE_SPECIAL,
        }

    def clear(self):
        proto_helpers.StringTransport.clear(self)
        self.transport = Container()
        self.transport.session = Container()
        self.transport.session.conn = Container()
        self.transport.session.conn.transport = Container()
        self.transport.session.conn.transport.transport = Container()
        self.transport.session.conn.transport.transport.sessionno = 1
        self.transport.session.conn.transport.factory = Container()
        self.transport.session.conn.transport.factory.sessions = {}
        self.transport.session.conn.transport.factory.starttime = 0
        self.factory = Container()
        self.session: dict[str, str] = {}
        self.eraseDisplay()

    def eraseDisplay(self):
        self.lines = [self._emptyLine(self.width) for i in range(self.height)]

    def _currentFormattingState(self):
        return True

    def _FormattingState(self):
        return True

    def _emptyLine(self, width):
        return [(self.void, self._currentFormattingState()) for i in range(width)]
