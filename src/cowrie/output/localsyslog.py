# Copyright (C) 2015 Michel Oosterhof <michel@oosterhof.net>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


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
