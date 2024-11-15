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

import json
import os

from twisted.python import log

import cowrie.core.output
import cowrie.python.logfile
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    jsonlog output
    """

    def start(self):
        self.epoch_timestamp = CowrieConfig.getboolean(
            "output_jsonlog", "epoch_timestamp", fallback=False
        )
        fn = CowrieConfig.get("output_jsonlog", "logfile", fallback="cowrie.json")
        dirs = os.path.dirname(fn)
        base = os.path.basename(fn)
        self.outfile = cowrie.python.logfile.CowrieDailyLogFile(
            base, dirs, defaultMode=0o664
        )

    def stop(self):
        if self.outfile:
            self.outfile.flush()

    def write(self, event):
        if self.epoch_timestamp:
            event["epoch"] = int(event["time"] * 1000000 / 1000)
        for i in list(event.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_") or i == "time" or i == "system":
                del event[i]
        try:
            json.dump(event, self.outfile, separators=(",", ":"))
            self.outfile.write("\n")
            self.outfile.flush()
        except TypeError:
            log.err("jsonlog: Can't serialize: '" + repr(event) + "'")
