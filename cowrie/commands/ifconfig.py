# -*- coding: utf-8 -*-
# Copyright (c) 2014 Peter Reuterås <peter@reuteras.com>
# See the COPYRIGHT file for more information

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_ifconfig(HoneyPotCommand):

    def call(self):
        l = """eth0      Link encap:Ethernet  HWaddr 04:01:16:df:2d:01
          inet addr:%s  Bcast:%s.255  Mask:255.255.255.0
          inet6 addr: fe80::601:16ff:fedf:2d01/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:139435762 errors:0 dropped:0 overruns:0 frame:0
          TX packets:116082382 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:102191499830 (102.1 GB)  TX bytes:68687923025 (68.6 GB)


lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:110 errors:0 dropped:0 overruns:0 frame:0
          TX packets:110 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:19932 (19.9 KB)  TX bytes:19932 (19.9 KB)""" % \
        (self.protocol.kippoIP,
        self.protocol.kippoIP.rsplit('.', 1)[0])
        self.write(l+'\n')

commands['/sbin/ifconfig'] = command_ifconfig

# vim: set sw=4 et:
