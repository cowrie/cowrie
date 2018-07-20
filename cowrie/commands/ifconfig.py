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

    def call(self):
        l = """eth0      Link encap:Ethernet  HWaddr %s
          inet addr:%s  Bcast:%s.255  Mask:255.255.255.0
          inet6 addr: %s Scope:Link
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
            (HWaddr, self.protocol.kippoIP,
             self.protocol.kippoIP.rsplit('.', 1)[0], inet6)
        self.write('{0}\n'.format(l))


commands['/sbin/ifconfig'] = command_ifconfig
commands['ifconfig'] = command_ifconfig
