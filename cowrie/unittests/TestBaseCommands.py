__author__ = 'davegermiquet'
from twisted.trial import unittest
from twisted.test import proto_helpers
from cowrie.core import protocol
from twisted.conch.insults import insults

import FakeServer

class Container(object):
    otherVersionString = "1.0"

    def getPeer(self):
        self.host  = "1.1.1.1"
        self.port = 2222

        return self


class TestFakeTransport(proto_helpers.StringTransport):
    """
    Fake transport with abortConnection() method.
    """
    for keyID in ('UP_ARROW', 'DOWN_ARROW', 'RIGHT_ARROW', 'LEFT_ARROW',
                  'HOME', 'INSERT', 'DELETE', 'END', 'PGUP', 'PGDN',
                  'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9',
                  'F10', 'F11', 'F12'):
        exec '%s = object()' % (keyID,)

    TAB = '\x09'
    BACKSPACE = '\x08'

    modes = {}
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
    transport = Container()
    transport.session = Container()
    transport.session.conn = Container()
    transport.session.conn.transport = Container()
    transport.session.conn.transport.transport = Container()
    transport.session.conn.transport.transport.sessionno = 1
    transport.session.conn.transport.factory = Container()
    transport.session.conn.transport.factory.sessions = {}
    factory = Container()
    session = {}

    def abortConnection(self):
        self.aborting = True

    def resetModes(self, modes):
        for m in modes:
            try:
                del self.modes[m]
            except KeyError:
                pass


class ShellFileCommands(unittest.TestCase):
    def setUp(self):

        self.proto = protocol.HoneyPotInteractiveProtocol(FakeServer.FakeAvatar(FakeServer.FakeServer("cowrie.cfg")))
        self.tr = TestFakeTransport("1.1.1.1","1111")
        self.proto.makeConnection(self.tr)


    def test_ls_command(self):
        self.proto.lineReceived('ls -la \n')
        print self.tr.value()
