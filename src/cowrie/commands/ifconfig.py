# -*- coding: utf-8 -*-
# Copyright (c) 2014 Peter Reuterås <peter@reuteras.com>
# See the COPYRIGHT file for more information

from __future__ import division, absolute_import

from cowrie.shell.command import HoneyPotCommand
from random import randrange, randint

HWaddr = "%02x:%02x:%02x:%02x:%02x:%02x" % (randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255), randint(0, 255))

inet6 = "fe%02x::%02x:%02xff:fe%02x:%02x01/64" % (randint(0, 255), randrange(111, 888), randint(0, 255), randint(0, 255), randint(0, 255))

commands = {}


class command_ifconfig(HoneyPotCommand):

    @staticmethod
    def generate_packets():
        return randrange(222222, 555555)

    @staticmethod
    def convert_bytes_to_mx(bytes_eth0):
        mb = float(bytes_eth0) / 1000 / 1000
        return "{0:.1f}".format(mb)

    def calculate_rx(self):
        rx_bytes = randrange(111111111, 555555555)
        return rx_bytes, self.convert_bytes_to_mx(rx_bytes)

    def calculate_tx(self):
        rx_bytes = randrange(11111111, 55555555)
        return rx_bytes, self.convert_bytes_to_mx(rx_bytes)

    def calculate_lo(self):
        lo_bytes = randrange(11111111, 55555555)
        return lo_bytes, self.convert_bytes_to_mx(lo_bytes)

    def call(self):
        rx_bytes_eth0, rx_mb_eth0 = self.calculate_rx()
        tx_bytes_eth0, tx_mb_eth0 = self.calculate_tx()
        lo_bytes, lo_mb = self.calculate_lo()
        rx_packets = self.generate_packets()
        tx_packets = self.generate_packets()
        l = """eth0      Link encap:Ethernet  HWaddr %s
          inet addr:%s  Bcast:%s.255  Mask:255.255.255.0
          inet6 addr: %s Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:%s errors:0 dropped:0 overruns:0 frame:0
          TX packets:%s errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:%s (%s MB)  TX bytes:%s (%s GB)


lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:110 errors:0 dropped:0 overruns:0 frame:0
          TX packets:110 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:%s (%s KB)  TX bytes:19932 (19.9 KB)""" % \
            (HWaddr, self.protocol.kippoIP,
             self.protocol.kippoIP.rsplit('.', 1)[0], inet6, rx_packets,
             tx_packets, rx_bytes_eth0, rx_mb_eth0, tx_bytes_eth0, tx_mb_eth0,
             )
        self.write('{0}\n'.format(l))


commands['/sbin/ifconfig'] = command_ifconfig
commands['ifconfig'] = command_ifconfig
