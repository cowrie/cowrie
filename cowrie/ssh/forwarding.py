# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import twisted
from twisted.conch.ssh import forwarding
from twisted.python import log


def CowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    """
    """
    remoteHP, origHP = twisted.conch.ssh.forwarding.unpackOpen_direct_tcpip(data)
    log.msg(eventid='cowrie.direct-tcpip.request', format='direct-tcp connection request to %(dst_ip)s:%(dst_port)s',
            dst_ip=remoteHP[0], dst_port=remoteHP[1])
    return CowrieConnectForwardingChannel(remoteHP,
       remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket,
       avatar=avatar)



class CowrieConnectForwardingChannel(forwarding.SSHConnectForwardingChannel):
    """
    """
    def channelOpen(self, specificData):
        """
        """
        pass


    def dataReceived(self, data):
        """
        """
        log.msg(eventid='cowrie.direct-tcpip.data',
            format='direct-tcp forward to %(dst_ip)s:%(dst_port)s with data %(data)s',
            dst_ip=self.hostport[0], dst_port=self.hostport[1], data=repr(data))
        self._close("Connection refused")

