# Copyright (C) 2024 Michel Oosterhof <michel@oosterhof.net>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

from twisted.conch.interfaces import IConchUser
from twisted.conch.telnet import ITelnetProtocol
from twisted.cred.portal import IRealm
from zope.interface import implementer

from cowrie.llm import avatar as llmavatar
from cowrie.llm import server as llmserver
from cowrie.llm import telnet as llmtelnet


@implementer(IRealm)
class HoneyPotRealm:
    def __init__(self) -> None:
        pass

    def requestAvatar(self, avatarId, _mind, *interfaces):
        user: IConchUser
        if IConchUser in interfaces:
            serv = llmserver.CowrieServer(self)
            user = llmavatar.CowrieUser(avatarId, serv)
            return interfaces[0], user, user.logout
        if ITelnetProtocol in interfaces:
            serv = llmserver.CowrieServer(self)
            user = llmtelnet.HoneyPotTelnetSession(avatarId, serv)
            return interfaces[0], user, user.logout
        raise NotImplementedError
