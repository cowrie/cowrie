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

"""
Docstring
"""

import json
import os
import Queue
import threading

from twisted.python import log
import twisted.python.logfile

import cowrie.core.output

class Output(cowrie.core.output.Output):
    """
    Docstring class
    """

    def __init__(self, cfg):
        cowrie.core.output.Output.__init__(self, cfg)
        fn = cfg.get('output_jsonlog', 'logfile')
        dirs = os.path.dirname(fn)
        base = os.path.basename(fn)

        # create the log queue with a default buffer size if none is specified in
        # the log file.
        buffer_size = 10000
        if cfg.has_option('output_jsonlog', 'buffer_size'):
            buffer_size = int(cfg.get('output_jsonlog', 'buffer_size'))
        self._log_writer_queue = Queue.Queue(maxsize=buffer_size)

        # allocate the output file
        self.outfile = twisted.python.logfile.DailyLogFile(base, dirs, defaultMode=0o664)

        # start the log writer thread
        self._log_writer_thread = threading.Thread(target=self._write_log)
        self._log_writer_thread.daemon = True
        self._log_writer_thread.start()

    def start(self):
        """
        """
        pass


    def stop(self):
        """
        """
        self._log_queue.join()
        self.outfile.flush()


    def write(self, logentry):
        """
        """
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]

        # TODO: There's a possibility that the queue is full when we do this put, which means
        # we'll lose the log item. We specifically use put_nowait so in that case it doesn't
        # block the main writer thread.
        try:
            self._log_writer_queue.put_nowait(json.dumps(logentry))
        except Queue.Full:
            log.err('Could not queue jsonlog item. Consider increasing buffer_size in [output_jsonlog] of your cowrie configuration')

    def _write_log(self):
        # there's a probability of hitting IO errors while attempting to write
        # for various reasons (for example, the disk is full). So, regardless
        # of what happens during the write, we always mark the queue item as done
        # so self.stop() can properly join on any remaining items.
        while True:
            item = self._log_writer_queue.get()
            try:
                self.outfile.write(item)
                self.outfile.write('\n')
                self.outfile.flush()
            finally:
                self._log_writer_queue.task_done()

