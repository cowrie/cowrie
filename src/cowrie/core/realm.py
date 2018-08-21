from __future__ import absolute_import, division

import twisted
from twisted.conch import interfaces as conchinterfaces
from twisted.conch.telnet import ITelnetProtocol
from twisted.python import log

from zope.interface import implementer

from cowrie.core.config import CONFIG
from cowrie.proxy import avatar as proxyavatar
from cowrie.proxy import server as proxyserver
from cowrie.shell import avatar as shellavatar
from cowrie.shell import server as shellserver
from cowrie.telnet import session


@implementer(twisted.cred.portal.IRealm)
class HoneyPotRealm(object):

    def __init__(self):
        pass

    def requestAvatar(self, avatarId, *interfaces):
        try:
            backend = CONFIG.get('honeypot', 'backend')
        except Exception:
            backend = 'shell'

        if backend == 'shell':
            if conchinterfaces.IConchUser in interfaces:
                serv = shellserver.CowrieServer(self)
                user = shellavatar.CowrieUser(avatarId, serv)
                return interfaces[0], user, user.logout
            elif ITelnetProtocol in interfaces:
                serv = shellserver.CowrieServer(self)
                user = session.HoneyPotTelnetSession(avatarId, serv)
                return interfaces[0], user, user.logout
            raise NotImplementedError("No supported interfaces found.")
        elif backend == 'proxy':
            if conchinterfaces.IConchUser in interfaces:
                serv = proxyserver.CowrieServer(self)
                user = proxyavatar.CowrieUser(avatarId, serv)
                return interfaces[0], user, user.logout
            elif ITelnetProtocol in interfaces:
                raise NotImplementedError("Telnet not yet supported for proxy mode.")
            log.msg('No supported interfaces found.')
            raise NotImplementedError("No supported interfaces found.")
        else:
            raise NotImplementedError("No supported backend found.")
