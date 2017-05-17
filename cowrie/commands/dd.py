# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
dd commands
"""

from os import path

from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *

commands = {}

class command_dd(HoneyPotCommand):
    """
    dd command
    """

    ddargs = {}

    def start(self):
        if not self.args or self.args[0] == '>':
            return

        for arg in self.args:
            if not arg.index('='):
                self.write('unknown operand: {}'.format(arg))
                HoneyPotCommand.exit()
            operand, value = arg.split('=')
            if operand not in ('if', 'bs', 'of', 'count'):
                self.write('unknown operand: {}'.format(operand))
                self.exit(success=False)
            self.ddargs[operand] = value

        if self.input_data:
            self.write(self.input_data)
        else:
            for arg in self.ddargs.keys():
                value = self.ddargs[arg]
                if arg == 'if':
                    pname = self.fs.resolve_path(value, self.protocol.cwd)
                    if self.fs.isdir(pname):
                        self.errorWrite('dd: {}: Is a directory\n'.format(value))
                        continue
                    try:
                        self.write(self.fs.file_contents(pname))
                        self.exit()
                    except:
                        self.errorWrite('dd: {}: No such file or directory\n'.format(value))
                        HoneyPotCommand.exit(self)



    def exit(self, success=True):
        if success == True:
            self.write('0+0 records in\n')
            self.write('0+0 records out\n')
            self.write('0 bytes transferred in 0.695821 secs (0 bytes/sec)\n')
        HoneyPotCommand.exit(self)


    def lineReceived(self, line):
        log.msg(eventid='cowrie.session.input',
                realm='dd',
                input=line,
                format='INPUT (%(realm)s): %(input)s')


    def handle_CTRL_D(self):
        self.exit()


commands['/bin/dd'] = command_dd

