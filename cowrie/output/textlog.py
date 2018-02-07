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

from __future__ import division, absolute_import

from twisted.python import log

import cowrie.core.output
import cowrie.core.cef
from cowrie.core.config import CONFIG

class Output(cowrie.core.output.Output):

    def __init__(self):
        """
        """
        self.format = CONFIG.get('output_textlog', 'format')
        self.outfile = open(CONFIG.get('output_textlog', 'logfile'), 'a')
        cowrie.core.output.Output.__init__(self)


    def start(self):
        """
        """
        pass


    def stop(self):
        """
        """
        pass


    def write(self, logentry):
        """
        """
        if self.format == 'cef':
            self.outfile.write(logentry['timestamp']+" ")
            self.outfile.write(cowrie.core.cef.formatCef(logentry)+'\n')
        else:
            self.outfile.write(logentry['timestamp']+" ")
            self.outfile.write(logentry['message']+"\n")
        self.outfile.flush()

