# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.

"""
This module contains the sleep command
"""

from twisted.internet import reactor

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_sleep(HoneyPotCommand):
    """
    Sleep
    """

    def done(self):
        """
        """
        self.protocol.no_prompt = False
        self.lineReceived('\n')
        self.exit()


    def start(self):
        """
        """
        if len(self.args) == 1:
            _time = int( self.args[0] )
            reactor.callLater(_time, self.done)
            self.protocol.no_prompt = True
        else:
            self.write('usage: sleep seconds\n')


commands['/bin/sleep'] = command_sleep

# vim: set sw=4 et tw=0:
