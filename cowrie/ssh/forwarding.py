# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains code for handling SSH forwarding requests
"""

from twisted.python import log
from twisted.conch.ssh import forwarding


def cowrieOpenConnectForwardingClient(remoteWindow, remoteMaxPacket, data, avatar):
    """
    This function will redirect an SSH forward request to a another address
    or will log the request and do nothing
    """
    cfg = avatar.cfg
    if cfg.has_option('forward_mapping', 'ports') and \
            cfg.get('forward_mapping', 'ports').lower() in \
            ('true', 'yes'):
        mappedPortsComma = cfg.get('forward_mapping', 'ports').split(',')
        mappedPorts = [int(x.strip()) for x in mappedPortsComma]
    else:
        mappedPorts = []

    remoteHP, origHP = forwarding.unpackOpen_direct_tcpip(data)

    log.msg(eventid='cowrie.direct-tcpip.request',
        format='direct-tcp connection request to %(dst_ip)s:%(dst_port)s from %(src_ip)s:%(src_port)s',
        dst_ip=remoteHP[0], dst_port=remoteHP[1],
        src_ip=origHP[0], src_port=origHP[1])

    portRule = 'port_{dst_port}'.format(dst_port=remoteHP[1])
    if remoteHP[1] in mappedPorts \
            and cfg.has_option('forward_mapping', portRule):
        newAddr = cfg.get('forward_mapping', portRule)
        newIp = newAddr.split(':')[0].strip()
        newPort = int(newAddr.split(':')[1].strip())
        remoteHPNew = (newIp, newPort)
        log.msg(eventid='cowrie.direct-tcpip.redirect',
            format='found custom port, redirecting to %(new_ip)s:%(new_port)s',
                 new_ip=newIp, new_port=newPort)
        return forwarding.SSHConnectForwardingChannel(remoteHPNew,
            remoteWindow=remoteWindow, remoteMaxPacket=remoteMaxPacket,
            avatar=avatar)

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

