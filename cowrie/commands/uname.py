#

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_uname(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0].strip() in ('-a', '--all'):
            self.writeln(
                'Linux %s 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux' % \
                self.protocol.hostname)
        elif len(self.args) and self.args[0].strip() in ('-r', '--kernel-release'):
            self.writeln( '3.2.0-4-amd64' )
        elif len(self.args) and self.args[0].strip() in ('-m', '--machine'):
            self.writeln( 'amd64' )
        else:
            self.writeln('Linux')

commands['/bin/uname'] = command_uname

