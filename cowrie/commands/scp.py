# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import getopt

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_scp(HoneyPotCommand):
    """
    """

    def help(self):
        """
        """
        self.write(
"""usage: scp [-12346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]
           [-l limit] [-o ssh_option] [-P port] [-S program]
           [[user@]host1:]file1 ... [[user@]host2:]file2\n""")


    def start(self):
        """
        """
        try:
            optlist, args = getopt.getopt(self.args, 'tdv:')
        except getopt.GetoptError as err:
            self.help()
            self.exit()
            return
        self.write( '\x00' )
        self.write( '\x00' )
        self.write( '\x00' )
        self.write( '\x00' )
        self.write( '\x00' )
        self.write( '\x00' )
        self.write( '\x00' )
        self.write( '\x00' )
        self.write( '\x00' )
        self.write( '\x00' )


    def lineReceived(self, line):
        """
        """
        log.msg( eventid='COW0008', realm='scp', input=line,
            format='INPUT (%(realm)s): %(input)s' )
        self.protocol.terminal.write( '\x00' )

commands['/usr/bin/scp'] = command_scp

# vim: set sw=4 et:
