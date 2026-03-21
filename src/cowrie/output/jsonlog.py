# Copyright (C) 2015 Michel Oosterhof <michel@oosterhof.net>
# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import json
import os
from pathlib import Path

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

        logtype = CowrieConfig.get("honeypot", "logtype", fallback="plain")
        if logtype == "rotating":
            self.outfile = cowrie.python.logfile.CowrieDailyLogFile(
                base, dirs, defaultMode=0o664
            )
        elif logtype == "plain":
            self.outfile = open(Path(dirs, base), "w", encoding="utf-8")
        else:
            raise ValueError

    def stop(self):
        if self.outfile:
            self.outfile.flush()

    def write(self, event):
        if self.epoch_timestamp:
            event["epoch"] = int(event["time"] * 1000000 / 1000)
        for i in list(event):
            # Remove twisted 15 legacy keys
            if i.startswith("log_") or i == "time" or i == "system":
                del event[i]
        try:
            json.dump(event, self.outfile, separators=(",", ":"))
            self.outfile.write("\n")
            self.outfile.flush()
        except TypeError:
            log.err("jsonlog: Can't serialize: '" + repr(event) + "'")
