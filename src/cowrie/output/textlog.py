from __future__ import absolute_import, division

import cowrie.core.cef
import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):

    def __init__(self):

        self.format = CONFIG.get('output_textlog', 'format')
        self.outfile = open(CONFIG.get('output_textlog', 'logfile'), 'a')
        cowrie.core.output.Output.__init__(self)

    def start(self):
        pass

    def stop(self):
        pass

    def write(self, logentry):
        if self.format == 'cef':
            self.outfile.write('{0} '.format(logentry['timestamp']))
            self.outfile.write('{0}\n'.format(cowrie.core.cef.formatCef(logentry)))
        else:
            self.outfile.write('{0} '.format(logentry['timestamp']))
            self.outfile.write('{0} '.format(logentry['session']))
            self.outfile.write('{0}\n'.format(logentry['message']))
        self.outfile.flush()
