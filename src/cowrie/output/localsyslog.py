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


from __future__ import annotations
import syslog

import twisted.python.syslog

import cowrie.core.cef
import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    localsyslog output
    """

    def start(self):
        self.format = CowrieConfig.get("output_localsyslog", "format")
        facilityString = CowrieConfig.get("output_localsyslog", "facility")
        self.facility = vars(syslog)["LOG_" + facilityString]
        self.syslog = twisted.python.syslog.SyslogObserver(
            prefix="cowrie", facility=self.facility
        )

    def stop(self):
        pass

    def write(self, event):
        if "isError" not in event:
            event["isError"] = False

        if "system" not in event:
            event["system"] = "cowrie"

        if self.format == "cef":
            self.syslog.emit(
                {
                    "message": [cowrie.core.cef.formatCef(event)],
                    "isError": False,
                    "system": "cowrie",
                }
            )
        else:
            # message appears with additional spaces if message key is defined
            event["message"] = [event["message"]]
            self.syslog.emit(event)
