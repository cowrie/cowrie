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

from __future__ import division, absolute_import

import abc
import datetime
import re
import copy
import socket
import time

from cowrie.core.config import CONFIG


# Events:
#  cowrie.client.fingerprint
#  cowrie.client.size
#  cowrie.client.var
#  cowrie.client.version
#  cowrie.command.input
#  cowrie.command.failed
#  cowrie.command.success (deprecated)
#  cowrie.direct-tcpip.data
#  cowrie.direct-tcpip.request
#  cowrie.log.closed
#  cowrie.log.open
#  cowrie.login.failed
#  cowrie.login.success
#  cowrie.session.closed
#  cowrie.session.connect
#  cowrie.session.file_download
#  cowrie.session.file_upload

"""
The time is available in two formats in each event, as key 'time'
in epoch format and in key 'timestamp' as a ISO compliant string
in UTC.
"""


def convert(input):
    """
    This converts a nested dictionary with bytes in it to string
    """
    if isinstance(input, dict):
        return {convert(key): convert(value) for key, value in list(input.items())}
    elif isinstance(input, list):
        return [convert(element) for element in input]
    elif isinstance(input, bytes):
        return input.decode('utf-8')
    else:
        return input


class Output(object):
    """
    This is the abstract base class intended to be inherited by
    cowrie output plugins. Plugins require the mandatory
    methods: stop, start and write
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self):
        self.sessions = {}
        self.ips = {}
        # Need these for each individual transport, or else the session numbers overlap
        self.sshRegex = re.compile(
            '.*SSHTransport,([0-9]+),[0-9a-f:.]+$')
        self.telnetRegex = re.compile(
            '.*TelnetTransport,([0-9]+),[0-9a-f:.]+$')
        try:
            self.sensor = CONFIG.get('honeypot', 'sensor_name')
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

        ev = convert(event)
        ev['sensor'] = self.sensor

        # Add ISO timestamp and sensor data
        if not 'time' in ev:
            ev['time'] = time.time()
        ev['timestamp'] = datetime.datetime.utcfromtimestamp(ev['time']).isoformat() + 'Z'

        if 'format' in ev and (not 'message' in ev or ev['message'] == ()):
            try:
                ev['message'] = ev['format'] % ev
                del ev['format']
            except:
                pass

        # On disconnect add the tty log
        #if ev['eventid'] == 'cowrie.log.closed':
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
            sessionno = 0
            telnetmatch = self.telnetRegex.match(ev['system'])
            if telnetmatch:
                sessionno = 'T'+str(telnetmatch.groups()[0])
            else:
                sshmatch = self.sshRegex.match(ev['system'])
                if sshmatch:
                    sessionno = 'S'+str(sshmatch.groups()[0])
            if sessionno == 0:
                return

        if sessionno in self.ips:
            ev['src_ip'] = self.ips[sessionno]

        # Connection event is special. adds to session list
        if ev['eventid'] == 'cowrie.session.connect':
            self.sessions[sessionno] = ev['session']
            self.ips[sessionno] = ev['src_ip']
        else:
            ev['session'] = self.sessions[sessionno]

        self.write(ev)

        # Disconnect is special, remove cached data
        if ev['eventid'] == 'cowrie.session.closed':
            del self.sessions[sessionno]
            del self.ips[sessionno]
