# Copyright (c) 2013 Bas Stottelaar <basstottelaar [AT] gmail [DOT] com>

import time
import re
import getopt
import socket
import random

from twisted.internet import reactor
from kippo.core.honeypot import HoneyPotCommand

commands = {}

class command_netstat(HoneyPotCommand):

    def show_version(self):
        self.writeln('net-tools 1.60')
        self.writeln('netstat 1.42 (2001-04-15)')
        self.writeln('Fred Baumgarten, Alan Cox, Bernd Eckenfels, Phil Blundell, Tuan Hoang and others')
        self.writeln('+NEW_ADDRT +RTF_IRTT +RTF_REJECT +FW_MASQUERADE +I18N')
        self.writeln('AF: (inet) +UNIX +INET +INET6 +IPX +AX25 +NETROM +X25 +ATALK +ECONET +ROSE')
        self.writeln('HW:  +ETHER +ARC +SLIP +PPP +TUNNEL +TR +AX25 +NETROM +X25 +FR +ROSE +ASH +SIT +FDDI +HIPPI +HDLC/LAPB +EUI64')
        self.exit()

    def show_help(self):
        self.writeln("""
usage: netstat [-vWeenNcCF] [<Af>] -r         netstat {-V|--version|-h|--help}
       netstat [-vWnNcaeol] [<Socket> ...]
       netstat { [-vWeenNac] -i | [-cWnNe] -M | -s }

        -r, --route              display routing table
        -i, --interfaces         display interface table
        -g, --groups             display multicast group memberships
        -s, --statistics         display networking statistics (like SNMP)
        -M, --masquerade         display masqueraded connections

        -v, --verbose            be verbose
        -W, --wide               don\'t truncate IP addresses
        -n, --numeric            don\'t resolve names
        --numeric-hosts          don\'t resolve host names
        --numeric-ports          don\'t resolve port names
        --numeric-users          don\'t resolve user names
        -N, --symbolic           resolve hardware names
        -e, --extend             display other/more information
        -p, --programs           display PID/Program name for sockets
        -c, --continuous         continuous listing

        -l, --listening          display listening server sockets

        -o, --timers             display timers
        -F, --fib                display Forwarding Information Base (default)
        -C, --cache              display routing cache instead of FIB

  <Socket>={-t|--tcp} {-u|--udp} {-w|--raw} {-x|--unix} --ax25 --ipx --netrom
  <AF>=Use \'-6|-4\' or \'-A <af>\' or \'--<af>\'; default: inet
  List of possible address families (which support routing):
    inet (DARPA Internet) inet6 (IPv6) ax25 (AMPR AX.25) 
    netrom (AMPR NET/ROM) ipx (Novell IPX) ddp (Appletalk DDP) 
    x25 (CCITT X.25)""")
        self.exit()

    def do_netstat_route(self):
        self.honeypot.writeln("""Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface""")
        if self.show_numeric:
            default = "default"
            lgateway = "0.0.0.0"
        else:
            default = "0.0.0.0"
            lgateway = "*"
        destination = self.honeypot.kippoIP.rsplit('.', 1)[0] + ".0"
        gateway = self.honeypot.kippoIP.rsplit('.', 1)[0] + ".1"
        l1 = "%s%s0.0.0.0         UG        0 0          0 eth0" % \
            ('{:<16}'.format(default),
            '{:<16}'.format(gateway))
        l2 = "%s%s255.255.255.0   U         0 0          0 eth0" % \
            ('{:<16}'.format(destination),
            '{:<16}'.format(lgateway))
        self.honeypot.writeln(l1)
        self.honeypot.writeln(l2)

    def do_netstat_normal(self):
        self.honeypot.writeln("""Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State""")
        s_name = self.honeypot.hostname
        c_port = str(self.honeypot.realClientPort)
        if self.show_numeric:
            s_port = "22"
            c_name = str(self.honeypot.clientIP)
            s_name = str(self.honeypot.kippoIP)
        else:
            s_port = "ssh"
            c_name = socket.gethostbyaddr(self.honeypot.clientIP)[0][:17]
        if self.show_listen or self.show_all:
            self.honeypot.writeln("tcp        0      0 *:ssh                   *:*                     LISTEN")
        if not self.show_listen or self.show_all:
            l = 'tcp        0    308 %s:%s%s%s:%s%s%s' % \
                (s_name, s_port,
                " "*(24-len(s_name+s_port)-1), c_name, c_port,
                " "*(24-len(c_name+c_port)-1), "ESTABLISHED")
            self.honeypot.writeln(l)
        if self.show_listen or self.show_all:
            self.honeypot.writeln("tcp6       0      0 [::]:ssh                [::]:*                  LISTEN")
        self.honeypot.writeln("""Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   Path""")
        if self.show_listen:
            self.honeypot.writeln("""unix  2      [ ACC ]     STREAM     LISTENING     8969     /var/run/acpid.socket
unix  2      [ ACC ]     STREAM     LISTENING     6807     @/com/ubuntu/upstart
unix  2      [ ACC ]     STREAM     LISTENING     7299     /var/run/dbus/system_bus_socket
unix  2      [ ACC ]     SEQPACKET  LISTENING     7159     /run/udev/control""")
        elif self.show_all:
            self.honeypot.writeln("""unix  2      [ ACC ]     STREAM     LISTENING     8969     /var/run/acpid.socket
unix  4      [ ]         DGRAM                    7445     /dev/log
unix  2      [ ACC ]     STREAM     LISTENING     6807     @/com/ubuntu/upstart
unix  2      [ ACC ]     STREAM     LISTENING     7299     /var/run/dbus/system_bus_socket
unix  2      [ ACC ]     SEQPACKET  LISTENING     7159     /run/udev/control
unix  3      [ ]         STREAM     CONNECTED     7323     
unix  3      [ ]         STREAM     CONNECTED     7348     /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     7330     
unix  2      [ ]         DGRAM                    8966     
unix  3      [ ]         STREAM     CONNECTED     7424     /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     7140     
unix  3      [ ]         STREAM     CONNECTED     7145     @/com/ubuntu/upstart
unix  3      [ ]         DGRAM                    7199     
unix  3      [ ]         STREAM     CONNECTED     7347     
unix  3      [ ]         STREAM     CONNECTED     8594     
unix  3      [ ]         STREAM     CONNECTED     7331     
unix  3      [ ]         STREAM     CONNECTED     7364     @/com/ubuntu/upstart
unix  3      [ ]         STREAM     CONNECTED     7423     
unix  3      [ ]         DGRAM                    7198     
unix  2      [ ]         DGRAM                    9570     
unix  3      [ ]         STREAM     CONNECTED     8619     @/com/ubuntu/upstart""")
        else:
            self.honeypot.writeln("""unix  4      [ ]         DGRAM                    7445     /dev/log
unix  3      [ ]         STREAM     CONNECTED     7323     
unix  3      [ ]         STREAM     CONNECTED     7348     /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     7330     
unix  2      [ ]         DGRAM                    8966     
unix  3      [ ]         STREAM     CONNECTED     7424     /var/run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     7140     
unix  3      [ ]         STREAM     CONNECTED     7145     @/com/ubuntu/upstart
unix  3      [ ]         DGRAM                    7199     
unix  3      [ ]         STREAM     CONNECTED     7347     
unix  3      [ ]         STREAM     CONNECTED     8594     
unix  3      [ ]         STREAM     CONNECTED     7331     
unix  3      [ ]         STREAM     CONNECTED     7364     @/com/ubuntu/upstart
unix  3      [ ]         STREAM     CONNECTED     7423     
unix  3      [ ]         DGRAM                    7198     
unix  2      [ ]         DGRAM                    9570     
unix  3      [ ]         STREAM     CONNECTED     8619     @/com/ubuntu/upstart""")

    def call(self):
        self.show_all = False
        self.show_numeric = False
        self.show_listen = False
        func = self.do_netstat_normal
        for x in self.args:
            if x.startswith('-') and x.count('a'):
                self.show_all = True
            if x.startswith('-') and x.count('n'):
                self.show_numeric = True
            if x.startswith('-') and x.count('l'):
                self.show_listen = True
            if x.startswith('-') and x.count('r'):
                func = self.do_netstat_route
            if x.startswith('-') and x.count('h'):
                func = self.show_help
            if x.startswith('-') and x.count('V'):
                func = self.show_version
        func()

# Definitions
commands['/bin/netstat'] = command_netstat
