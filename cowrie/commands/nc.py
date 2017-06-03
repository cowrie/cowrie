import getopt
import re
import socket

from cowrie.core.honeypot import HoneyPotCommand

commands = {}


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

        host = args[0]
        port = args[1]

        if not re.match('[\d]+', port):
            self.errorWrite('nc: port number invalid: {}\n'.format(port))
            self.exit()

        out_addr = None
        if self.protocol.cfg.has_option('honeypot', 'out_addr'):
            out_addr = (self.protocol.cfg.get('honeypot', 'out_addr'), 0)
        else:
            out_addr = '0.0.0.0'

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((out_addr, 0))
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

        self.s.send(line)

    def handle_CTRL_C(self):

        self.write('^C\n')
        self.s.close()

    def handle_CTRL_D(self):

        self.s.close()

commands['/bin/nc'] = command_nc
