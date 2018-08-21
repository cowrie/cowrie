from __future__ import absolute_import, division

import syslog

import twisted.python.syslog

import cowrie.core.cef
import cowrie.core.output
from cowrie.core.config import CONFIG


class Output(cowrie.core.output.Output):

    def __init__(self):
        facilityString = CONFIG.get('output_localsyslog', 'facility')
        self.format = CONFIG.get('output_localsyslog', 'format')
        self.facility = vars(syslog)['LOG_' + facilityString]
        self.syslog = twisted.python.syslog.SyslogObserver(prefix='cowrie', facility=self.facility)
        cowrie.core.output.Output.__init__(self)

    def start(self):
        pass

    def stop(self):
        pass

    def write(self, logentry):
        if self.format == 'cef':
            self.syslog.emit({
                'message': cowrie.core.cef.formatCef(logentry),
                'isError': False,
                'system': 'cowrie'
            })
        else:
            # message appears with additional spaces if message key is defined
            logentry['message'] = [logentry['message']]
            self.syslog.emit(logentry)
