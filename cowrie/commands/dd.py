# Copyright (c) 2016 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
dd commands
"""

from __future__ import division, absolute_import

from os import path

from cowrie.shell.honeypot import HoneyPotCommand
from cowrie.shell.fs import *

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
                HoneyPotCommand.exit(self)
            operand, value = arg.split('=')
            if operand not in ('if', 'bs', 'of', 'count'):
                self.write('unknown operand: {}'.format(operand))
                self.exit(success=False)
            self.ddargs[operand] = value

        if self.input_data:
            self.write(self.input_data)
        else:
            bSuccess = True
            c = -1
            block = 512
            if 'if' in self.ddargs:
                iname = self.ddargs['if']
                pname = self.fs.resolve_path(iname, self.protocol.cwd)
                if self.fs.isdir(pname):
                    self.errorWrite('dd: {}: Is a directory\n'.format(iname))
                    bSuccess = False

                if bSuccess:
                    if 'bs' in self.ddargs:
                        block = int(self.ddargs['bs'])
                        if block <= 0:
                            self.errorWrite('dd: invalid number \'{}\'\n'.format(block))
                            bSuccess = False

                if bSuccess:
                    if 'count' in self.ddargs:
                        c = int(self.ddargs['count'])
                        if c < 0:
                            self.errorWrite('dd: invalid number \'{}\'\n'.format(c))
                            bSuccess = False

                if bSuccess:
                    try:
                        contents = self.fs.file_contents(pname)
                        if c == -1:
                            self.write(contents)
                        else:
                            tsize = block * c
                            data = contents
                            if len(data) > tsize:
                                self.write(data[:tsize])
                            else:
                                self.write(data)
                    except:
                        self.errorWrite('dd: {}: No such file or directory\n'.format(iname))
                        bSuccess = False

                self.exit(success=bSuccess)



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

