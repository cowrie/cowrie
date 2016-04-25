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
    cfg = avatar.cfg
    remoteHP, origHP = twisted.conch.ssh.forwarding.unpackOpen_direct_tcpip(data)
    log.msg(eventid='cowrie.direct-tcpip.request', 
    format='direct-tcp connection request to %(dst_ip)s:%(dst_port)s from %(src_ip)s:%(src_port)s',
            dst_ip=remoteHP[0], dst_port=remoteHP[1],
            src_ip=origHP[0], src_port=origHP[1])
    if cfg.has_option('honeypot', 'smtp_forwarding_enabled') and \
            cfg.get('honeypot', 'smtp_forwarding_enabled').lower() in \
            ('yes', 'true', 'on'):
        honey_smtp = True
        honey_port = int(cfg.get('honeypot', 'smtp_forwarding_port'))
        honey_host  = cfg.get('honeypot', 'smtp_forwarding_host')
    else:
        honey_smtp= False

    if remoteHP[1] == 25 and honey_smtp:
        log.msg(eventid='cowrie.direct-tcpip.request',format='found smtp, forwarding to local honeypot')
        remoteHPLocal = (honey_host, honey_port)
        return forwarding.SSHConnectForwardingChannel(remoteHPLocal,
            remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket,
            avatar=avatar)
    else:
        pass
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

