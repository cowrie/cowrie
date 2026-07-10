# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

from typing import TYPE_CHECKING

from twisted.cred.credentials import ICredentials, IUsernamePassword
from zope.interface import implementer

if TYPE_CHECKING:
    from collections.abc import Callable

    from cowrie.core.events import EventLog


class IUsername(ICredentials):
    """
    Encapsulate username only

    @type username: C{bytes}
    @ivar username: The username associated with these credentials.
    """


class IUsernamePasswordIP(IUsernamePassword):
    """
    I encapsulate a username, a plaintext password and a source IP

    @type username: C{bytes}
    @ivar username: The username associated with these credentials.

    @type password: C{bytes}
    @ivar password: The password associated with these credentials.

    @type ip: C{str}
    @ivar ip: The source ip address associated with these credentials.
    """


class IPluggableAuthenticationModulesIP(ICredentials):
    """
    Twisted removed IPAM in 15, adding in Cowrie now
    """


@implementer(IPluggableAuthenticationModulesIP)
class PluggableAuthenticationModulesIP:
    """
    Twisted removed IPAM in 15, adding in Cowrie now
    """

    def __init__(
        self,
        username: bytes,
        pamConversion: Callable,
        ip: str,
        events: EventLog | None = None,
    ) -> None:
        self.username: bytes = username
        self.pamConversion: Callable = pamConversion
        self.ip: str = ip
        self.events: EventLog | None = events


@implementer(IUsername)
class Username:
    def __init__(self, username: bytes, events: EventLog | None = None):
        self.username: bytes = username
        self.events: EventLog | None = events


@implementer(IUsernamePasswordIP)
class UsernamePasswordIP:
    """
    This credential interface also provides an IP address
    """

    def __init__(
        self,
        username: bytes,
        password: bytes,
        ip: str,
        events: EventLog | None = None,
    ) -> None:
        self.username: bytes = username
        self.password: bytes = password
        self.ip: str = ip
        self.events: EventLog | None = events

    def checkPassword(self, password: bytes) -> bool:
        return self.password == password
