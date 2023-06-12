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

import abc
import re
import socket
import time
from os import environ
from typing import Any
from re import Pattern

from twisted.internet import reactor
from twisted.logger import formatTime

from cowrie.core.config import CowrieConfig

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
#  cowrie.login.failed
#  cowrie.login.success
#  cowrie.session.closed
#  cowrie.session.connect
#  cowrie.session.file_download
#  cowrie.session.file_upload


# The time is available in two formats in each event, as key 'time'
# in epoch format and in key 'timestamp' as a ISO compliant string
# in UTC.


def convert(data):
    """
    This converts a nested dictionary with bytes in it to string
    """
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        return {convert(key): convert(value) for key, value in list(data.items())}
    if isinstance(data, dict):
        return {convert(key): convert(value) for key, value in list(data.items())}
    if isinstance(data, list):
        return [convert(element) for element in data]
    if isinstance(data, bytes):
        try:
            string = data.decode("utf-8")
        except UnicodeDecodeError:
            string = repr(data)
        return string
    return data


class Output(metaclass=abc.ABCMeta):
    """
    This is the abstract base class intended to be inherited by
    cowrie output plugins. Plugins require the mandatory
    methods: stop, start and write
    """

    def __init__(self) -> None:
        self.sessions: dict[str, str] = {}
        self.ips: dict[str, str] = {}

        # Need these for each individual transport, or else the session numbers overlap
        self.sshRegex: Pattern[str] = re.compile(".*SSHTransport,([0-9]+),[0-9a-f:.]+$")
        self.telnetRegex: Pattern[str] = re.compile(
            ".*TelnetTransport,([0-9]+),[0-9a-f:.]+$"
        )
        self.sensor: str = CowrieConfig.get(
            "honeypot", "sensor_name", fallback=socket.gethostname()
        )
        self.timeFormat: str

        # use Z for UTC (Zulu) time, it's shorter.
        if "TZ" in environ and environ["TZ"] == "UTC":
            self.timeFormat = "%Y-%m-%dT%H:%M:%S.%fZ"
        else:
            self.timeFormat = "%Y-%m-%dT%H:%M:%S.%f%z"

        # Event trigger so that stop() is called by the reactor when stopping
        reactor.addSystemEventTrigger("before", "shutdown", self.stop)  # type: ignore

        self.start()

    def logDispatch(self, **kw: str) -> None:
        """
        Use logDispatch when the HoneypotTransport prefix is not available.
        Here you can explicitly set the sessionIds to tie the sessions together
        """
        ev = kw
        # ev["message"] = msg
        self.emit(ev)

    @abc.abstractmethod
    def start(self) -> None:
        """
        Abstract method to initialize output plugin
        """
        pass

    @abc.abstractmethod
    def stop(self) -> None:
        """
        Abstract method to shut down output plugin
        """
        pass

    @abc.abstractmethod
    def write(self, event: dict[str, Any]) -> None:
        """
        Handle a general event within the output plugin
        """
        pass

    def emit(self, event: dict) -> None:
        """
        This is the main emit() hook that gets called by the the Twisted logging

        To make this work with Cowrie, the event dictionary needs the following keys:
        - 'eventid'
        - 'sessionno' or 'session'
        - 'message' or 'format'
        """
        sessionno: str
        ev: dict

        # Ignore stdout and stderr in output plugins
        if "printed" in event:
            return

        # Ignore anything without eventid
        if "eventid" not in event:
            return

        # Ignore anything without session information
        if (
            "sessionno" not in event
            and "session" not in event
            and "system" not in event
        ):
            return

        # Ignore anything without message
        if "message" not in event and "format" not in event:
            return

        ev: dict[str, any] = convert(event)  # type: ignore
        ev["sensor"] = self.sensor

        if "isError" in ev:
            del ev["isError"]

        # Add ISO timestamp and sensor data
        if "time" not in ev:
            ev["time"] = time.time()
        ev["timestamp"] = formatTime(ev["time"], timeFormat=self.timeFormat)

        if "format" in ev and ("message" not in ev or ev["message"] == ()):
            try:
                ev["message"] = ev["format"] % ev
                del ev["format"]
            except Exception:
                pass

        # Explicit sessionno (from logDispatch) overrides from 'system'
        if "sessionno" in ev:
            sessionno = ev["sessionno"]
            del ev["sessionno"]
        # Maybe it's passed explicitly
        elif "session" in ev:
            # reverse engineer sessionno
            try:
                sessionno = next(
                    key
                    for key, value in self.sessions.items()
                    if value == ev["session"]
                )
            except StopIteration:
                return
        # Extract session id from the twisted log prefix
        elif "system" in ev:
            sessionno = "0"
            telnetmatch = self.telnetRegex.match(ev["system"])
            if telnetmatch:
                sessionno = f"T{telnetmatch.groups()[0]}"
            else:
                sshmatch = self.sshRegex.match(ev["system"])
                if sshmatch:
                    sessionno = f"S{sshmatch.groups()[0]}"
            if sessionno == "0":
                return

        if sessionno in self.ips:
            ev["src_ip"] = self.ips[sessionno]

        # Connection event is special. adds to session list
        if ev["eventid"] == "cowrie.session.connect":
            self.sessions[sessionno] = ev["session"]
            self.ips[sessionno] = ev["src_ip"]
        else:
            ev["session"] = self.sessions[sessionno]

        self.write(ev)

        # Disconnect is special, remove cached data
        if ev["eventid"] == "cowrie.session.closed":
            del self.sessions[sessionno]
            del self.ips[sessionno]
