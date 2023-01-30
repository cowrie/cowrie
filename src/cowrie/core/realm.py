# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
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

from __future__ import annotations

from zope.interface import implementer

from twisted.conch.interfaces import IConchUser
from twisted.conch.telnet import ITelnetProtocol
from twisted.cred.portal import IRealm

from cowrie.shell import avatar as shellavatar
from cowrie.shell import server as shellserver
from cowrie.telnet import session


@implementer(IRealm)
class HoneyPotRealm:
    def __init__(self) -> None:
        pass

    def requestAvatar(self, avatarId, _mind, *interfaces):
        user: IConchUser
        if IConchUser in interfaces:
            serv = shellserver.CowrieServer(self)
            user = shellavatar.CowrieUser(avatarId, serv)
            return interfaces[0], user, user.logout
        if ITelnetProtocol in interfaces:
            serv = shellserver.CowrieServer(self)
            user = session.HoneyPotTelnetSession(avatarId, serv)
            return interfaces[0], user, user.logout
        raise NotImplementedError
