#

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_uname(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0].strip() in ('-a', '--all'):
            self.write(
                'Linux %s 3.2.0-4-amd64 #1 SMP Debian 3.2.68-1+deb7u1 x86_64 GNU/Linux\n' % \
                self.protocol.hostname)
        elif len(self.args) and self.args[0].strip() in ('-r', '--kernel-release'):
            self.write( '3.2.0-4-amd64\n' )
        elif len(self.args) and self.args[0].strip() in ('-m', '--machine'):
            self.write( 'amd64\n' )
        else:
            self.write('Linux\n')

commands['/bin/uname'] = command_uname

