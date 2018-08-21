from __future__ import absolute_import, division

import json
import os

import cowrie.core.output
import cowrie.python.logfile
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):

    def __init__(self):
        cowrie.core.output.Output.__init__(self)
        fn = CONFIG.get('output_jsonlog', 'logfile')
        dirs = os.path.dirname(fn)
        base = os.path.basename(fn)
        self.outfile = cowrie.python.logfile.CowrieDailyLogFile(base, dirs, defaultMode=0o664)

    def start(self):
        pass

    def stop(self):
        self.outfile.flush()

    def write(self, logentry):
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith('log_') or i == 'time' or i == 'system':
                del logentry[i]
        json.dump(logentry, self.outfile)
        self.outfile.write('\n')
        self.outfile.flush()
