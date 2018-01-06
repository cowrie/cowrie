# Copyright (c) 2009-2014 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains code for handling SSH direct-tcpip connection requests
"""

from __future__ import division, absolute_import

from twisted.python import log
from twisted.conch.ssh import forwarding

def cowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    """
    This function will redirect an SSH forward request to a another address
    or will log the request and do nothing
    """
    remoteHP, origHP = forwarding.unpackOpen_direct_tcpip(data)

    log.msg(eventid='cowrie.direct-tcpip.request',
        format='direct-tcp connection request to %(dst_ip)s:%(dst_port)s from %(src_ip)s:%(src_port)s',
        dst_ip=remoteHP[0], dst_port=remoteHP[1],
        src_ip=origHP[0], src_port=origHP[1])

    cfg = avatar.cfg
    try:
        if cfg.getboolean('ssh', 'forward_redirect') == True:
            redirectEnabled = True
        else:
            redirectEnabled = False
    except:
        redirectEnabled = False

    if redirectEnabled:
        redirects = {}
        items = cfg.items('ssh')
        for i in items:
            if i[0].startswith('forward_redirect_'):
                destPort = i[0].split('_')[-1]
                redirectHP = i[1].split(':')
                redirects[int(destPort)] = (redirectHP[0], int(redirectHP[1]))
        if remoteHP[1] in redirects:
            remoteHPNew = redirects[remoteHP[1]]
            log.msg(eventid='cowrie.direct-tcpip.redirect',
                format='redirected direct-tcp connection request %(src_ip)s:%(src_port)d->%(dst_ip)s:%(dst_port)d to %(new_ip)s:%(new_port)d',
                    new_ip=remoteHPNew[0], new_port=remoteHPNew[1],
                    dst_ip=remoteHP[0], dst_port=remoteHP[1],
                    src_ip=origHP[0], src_port=origHP[1])
            return SSHConnectForwardingChannel(remoteHPNew,
                remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket)

    return FakeForwardingChannel(remoteHP,
           remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket)



class SSHConnectForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    This class modifies the original to close the connection
    """
    name = b'cowrie-forwarded-direct-tcpip'


    def eofReceived(self):
        self.loseConnection()



class FakeForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    This channel does not forward, but just logs requests.
    """
    name = b'cowrie-discarded-direct-tcpip'

    def channelOpen(self, specificData):
        """
        """
        pass


    def dataReceived(self, data):
        """
        """
        log.msg(eventid='cowrie.direct-tcpip.data',
            format='discarded direct-tcp forward request to %(dst_ip)s:%(dst_port)s with data %(data)s',
            dst_ip=self.hostport[0], dst_port=self.hostport[1], data=repr(data))
        self._close("Connection refused")

