# Copyright (c) 2013 Thomas Nicholson <tnnich@googlemail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from twisted.conch.ssh import transport
from twisted.python import log

class CowrieSSHServerTransport(transport.SSHServerTransport):
    def connectionMade(self):
        """
        Called when the connection is made to the other side.  We sent our
        version and the MSG_KEXINIT packet.
        """
        self.transport.write('%s\r\n' % (self.ourVersionString,))
        self.currentEncryptions = transport.SSHCiphers('none', 'none', 'none', 'none')
        self.currentEncryptions.setKeys('', '', '', '', '', '')

    def dataReceived(self, data):
        """
        First, check for the version string (SSH-2.0-*).  After that has been
        received, this method adds data to the buffer, and pulls out any
        packets.

        @type data: C{str}
        """
        self.buf = self.buf + data
        if not self.gotVersion:
            if not '\n' in self.buf:
                return
            self.otherVersionString = self.buf.strip()
            if self.buf.startswith('SSH-'):
                self.gotVersion = True
                remoteVersion = self.buf.split('-')[1]
                if remoteVersion not in self.supportedVersions:
                    self._unsupportedVersionReceived(remoteVersion)
                    return
                i = self.buf.index('\n')
                self.buf = self.buf[i+1:]
                self.sendKexInit()
            else:
                self.transport.write('Protocol mismatch.\n')
                log.msg('Bad protocol version identification: %s' % (self.otherVersionString))
                self.transport.loseConnection()
                return
        packet = self.getPacket()
        while packet:
            messageNum = ord(packet[0])
            self.dispatchMessage(messageNum, packet[1:])
            packet = self.getPacket()

    def sendDisconnect(self, reason, desc):
        """
        http://kbyte.snowpenguin.org/portal/2013/04/30/kippo-protocol-mismatch-workaround/
        Workaround for the "bad packet length" error message.

        @param reason: the reason for the disconnect.  Should be one of the
                       DISCONNECT_* values.
        @type reason: C{int}
        @param desc: a descrption of the reason for the disconnection.
        @type desc: C{str}
        """
        if not 'bad packet length' in desc:
            # With python >= 3 we can use super?
            transport.SSHServerTransport.sendDisconnect(self, reason, desc)
        else:
            self.transport.write('Protocol mismatch.\n')
            log.msg('[SERVER] - Disconnecting with error, code %s\nreason: %s' % (reason, desc))
            self.transport.loseConnection()

