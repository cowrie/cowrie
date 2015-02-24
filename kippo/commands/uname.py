# 

from kippo.core.honeypot import HoneyPotCommand

commands = {}

class command_uname(HoneyPotCommand):
    def call(self):
        if len(self.args) and self.args[0].strip() in ('-a', '--all'):
            self.writeln(
                'Linux %s 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:37 UTC 2009 i686 GNU/Linux' % \
                self.honeypot.hostname)
        elif len(self.args) and self.args[0].strip() in ('-r', '--kernel-release'):
            self.writeln( '2.6.26-2-686' )
        elif len(self.args) and self.args[0].strip() in ('-m', '--machine'):
            self.writeln( 'i686' )
        else:
            self.writeln('Linux')

commands['/bin/uname'] = command_uname

