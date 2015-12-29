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
This module contains ...
"""

import abc
import datetime
import re
import copy
import socket

# COW0001 : create session
# COW0002 : succesful login
# COW0003 : failed login
# COW0004 : TTY log opened
# COW0005 : handle command
# COW0006 : handle unknown command
# COW0007 : file download
# COW0008 : INPUT
# COW0009 : SSH Version
# COW0010 : Terminal Size
# COW0011 : Connection Lost
# COW0012 : TTY log closed
# COW0013 : env var requested
# COW0014 : direct-tcpip request
# COW0015 : direct-tcpip data
# COW0016 : key fingerprint

class Output(object):
    """
    This is the abstract base class intended to be inherited by cowrie output plugins
    Plugins require the mandatory methods: stop, start and write
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, cfg):
        self.cfg = cfg
        self.sessions = {}
        self.ips = {}
        self.re_sessionlog = re.compile(
            '.*HoneyPotTransport,([0-9]+),[0-9.]+$')
        try:
            self.sensor = self.cfg.get('honeypot', 'sensor_name')
        except:
            self.sensor = socket.gethostname()

        self.start()


    def logDispatch(self, *msg, **kw):
        """
        Use logDispatch when the HoneypotTransport prefix is not available.
        Here you can explicitly set the sessionIds to tie the sessions together
        """
        ev = kw
        ev['message'] = msg
        self.emit(ev)


    @abc.abstractmethod
    def start(self):
        """
        Abstract method to initialize output plugin
        """
        pass


    @abc.abstractmethod
    def stop(self):
        """
        Abstract method to shut down output plugin
        """
        pass


    @abc.abstractmethod
    def write(self, event):
        """
        Handle a general event within the output plugin
        """
        pass


    def emit(self, event):
        """
        This is the main emit() hook that gets called by the the Twisted logging
        """
        # Ignore stdout and stderr in output plugins
        if 'printed' in event:
            return

        # Ignore anything without eventid
        if not 'eventid' in event:
            return

        ev = copy.copy(event)

        ev['sensor'] = self.sensor

        # Add ISO timestamp and sensor data
        if not 'time' in ev:
            ev['timestamp'] = datetime.datetime.today().isoformat() + 'Z'
        else:
            ev['timestamp'] = datetime.datetime.fromtimestamp(ev['time']).isoformat() + 'Z'
            del ev['time']

        # On disconnect add the tty log
        #if ev['eventid'] == 'COW0012':
            # FIXME: file is read for each output plugin
            #f = file(ev['ttylog'])
            #ev['ttylog'] = f.read(10485760)
            #f.close()
            #pass

        # Explicit sessionno (from logDispatch) overrides from 'system'
        if 'sessionno' in ev:
            sessionno = ev['sessionno']
            del ev['sessionno']
        # Extract session id from the twisted log prefix
        elif 'system' in ev:
            match = self.re_sessionlog.match(ev['system'])
            if not match:
                return
            sessionno = int(match.groups()[0])

        if sessionno in self.ips:
            ev['src_ip'] = self.ips[sessionno]

        # Connection event is special. adds to session list
        if ev['eventid'] == 'COW0001':
            self.sessions[sessionno] = ev['id']
            self.ips[sessionno] = ev['src_ip']
            del ev['id']

        ev['session'] = self.sessions[sessionno]

        self.write(ev)

        # Disconnect is special, remove cached data
        if ev['eventid'] == 'COW0011':
            del self.sessions[sessionno]
            del self.ips[sessionno]

