from __future__ import division, absolute_import

import getopt
import re
import socket
import struct
import sys

from cowrie.shell.honeypot import HoneyPotCommand

if sys.version_info > (3,):
    long = int

commands = {}

def makeMask(n):
    """return a mask of n bits as a long integer"""
    return (long(2) << n - 1) - 1



def dottedQuadToNum(ip):
    """convert decimal dotted quad string to long integer"""
    return struct.unpack('I', socket.inet_aton(ip))[0]



def networkMask(ip, bits):
    """Convert a network address to a long integer"""
    return dottedQuadToNum(ip) & makeMask(bits)



def addressInNetwork(ip, net):
    """Is an address in a network"""
    return ip & net == net


local_networks = [networkMask('10.0.0.0', 8), networkMask('172.16.0.0', 12), networkMask('192.168.0.0', 16)]


class command_nc(HoneyPotCommand):
    def help(self):
        """
        """
        self.write(
            """This is nc from the netcat-openbsd package. An alternative nc is available
in the netcat-traditional package.
usage: nc [-46bCDdhjklnrStUuvZz] [-I length] [-i interval] [-O length]
          [-P proxy_username] [-p source_port] [-q seconds] [-s source]
          [-T toskeyword] [-V rtable] [-w timeout] [-X proxy_protocol]
          [-x proxy_address[:port]] [destination] [port]\n""")


    def start(self):
        """
        """

        try:
            optlist, args = getopt.getopt(self.args, '46bCDdhklnrStUuvZzI:i:O:P:p:q:s:T:V:w:X:x:')
        except getopt.GetoptError as err:
            self.help()
            self.exit()
            return

        if not args or len(args) < 2:
            self.help()
            self.exit()
            return

        host = args[0]
        port = args[1]

        address = dottedQuadToNum(host)

        for net in local_networks:
            if addressInNetwork(address, net):
                self.exit()
                return

        if not re.match('[\d]+', port):
            self.errorWrite('nc: port number invalid: {}\n'.format(port))
            self.exit()
            return

        out_addr = None
        if self.protocol.cfg.has_option('honeypot', 'out_addr'):
            out_addr = (self.protocol.cfg.get('honeypot', 'out_addr'), 0)
        else:
            out_addr = ('0.0.0.0', 0)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind(out_addr)
        self.s.connect((host, int(port)))
        self.recv_data()


    def recv_data(self):

        data = ''

        while 1:
            packet = self.s.recv(1024)
            if packet == '':
                break
            else:
                data += packet

        self.write(data)
        self.s.close()
        self.exit()


    def lineReceived(self, line):

        if hasattr(self, 's'):
            self.s.send(line)


    def handle_CTRL_C(self):

        self.write('^C\n')
        if hasattr(self, 's'):
            self.s.close()


    def handle_CTRL_D(self):

        if hasattr(self, 's'):
            self.s.close()


commands['/bin/nc'] = command_nc
