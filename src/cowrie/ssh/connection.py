# SPDX-FileCopyrightText: 2015-2023 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
This module contains connection code to work around issues with the
Granados SSH client library.
"""

from __future__ import annotations

import struct

from twisted.conch.ssh import common, connection
from twisted.internet import defer
from twisted.python import log


class CowrieSSHConnection(connection.SSHConnection):
    """
    Subclass this for a workaround for the Granados SSH library.
    Channel request for openshell needs to return success immediatly
    """

    def ssh_CHANNEL_REQUEST(self, packet):
        localChannel = struct.unpack(">L", packet[:4])[0]
        requestType, rest = common.getNS(packet[4:])
        wantReply = ord(rest[0:1])
        channel = self.channels[localChannel]

        if requestType == b"shell":
            wantReply = 0
            self.transport.sendPacket(
                connection.MSG_CHANNEL_SUCCESS,
                struct.pack(">L", self.localToRemoteChannel[localChannel]),
            )

        d = defer.maybeDeferred(
            log.callWithLogger, channel, channel.requestReceived, requestType, rest[1:]
        )
        if wantReply:
            d.addCallback(self._cbChannelRequest, localChannel)
            d.addErrback(self._ebChannelRequest, localChannel)
        return d
