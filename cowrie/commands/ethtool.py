# -*- coding: utf-8 -*-
# Copyright (c) 2014 Peter Reuterås <peter@reuteras.com>
# See the COPYRIGHT file for more information

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_ethtool(HoneyPotCommand):
    """
    """

    def call(self):
        """
        """
        func = self.do_ethtool_help
        for x in self.args:
            if x.startswith('lo'):
                func = self.do_ethtool_lo
            if x.startswith('eth0'):
                func = self.do_ethtool_eth0
            if x.startswith('eth1'):
                func = self.do_ethtool_eth1
        func()


    def do_ethtool_help(self):
        """
        No real help output.
        """
        self.write("""ethtool: bad command line argument(s)
For more information run ethtool -h\n""")


    def do_ethtool_lo(self):
        """
        """
        self.write("""Settings for lo:
            Link detected: yes\n""")


    def do_ethtool_eth0(self):
        """
        """
        self.write("""Settings for eth0:
Supported ports: [ TP MII ]
Supported link modes:   10baseT/Half 10baseT/Full
                        100baseT/Half 100baseT/Full
                        1000baseT/Half 1000baseT/Full
Supported pause frame use: No
Supports auto-negotiation: Yes
Advertised link modes:  10baseT/Half 10baseT/Full
                        100baseT/Half 100baseT/Full
                        1000baseT/Half 1000baseT/Full
Advertised pause frame use: Symmetric Receive-only
Advertised auto-negotiation: Yes
Link partner advertised link modes:  10baseT/Half 10baseT/Full
                                     100baseT/Half 100baseT/Full
                                     1000baseT/Full
Link partner advertised pause frame use: Symmetric Receive-only
Link partner advertised auto-negotiation: Yes
Speed: 1000Mb/s
Duplex: Full
Port: MII
PHYAD: 0
Transceiver: internal
Auto-negotiation: on
Supports Wake-on: pumbg
Wake-on: g
Current message level: 0x00000033 (51)
                       drv probe ifdown ifup
Link detected: yes\n""")


    def do_ethtool_eth1(self):
        """
        """
        self.write("""Settings for eth1:
Cannot get device settings: No such device
Cannot get wake-on-lan settings: No such device
Cannot get message level: No such device
Cannot get link status: No such device
No data available\n""")

commands['/sbin/ethtool'] = command_ethtool

# vim: set sw=4 et:
