# -*- test-case-name: cowrie.test.utils -*-
# Copyright (c) 2017 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information


from __future__ import annotations

from os import environ

from twisted.logger import textFileLogObserver
from twisted.python import logfile

from cowrie.core.config import CowrieConfig


class CowrieDailyLogFile(logfile.DailyLogFile):
    """
    Overload original Twisted with improved date formatting
    """

    def suffix(self, tupledate):
        """
        Return the suffix given a (year, month, day) tuple or unixtime
        """
        try:
            return f"{tupledate[0]:02d}-{tupledate[1]:02d}-{tupledate[2]:02d}"
        except Exception:
            # try taking a float unixtime
            return "_".join(map(str, self.toDate(tupledate)))


def logger():
    directory = CowrieConfig.get("honeypot", "log_path", fallback="var/log/cowrie")
    logfile = CowrieDailyLogFile("cowrie.log", directory)

    # use Z for UTC (Zulu) time, it's shorter.
    if "TZ" in environ and environ["TZ"] == "UTC":
        timeFormat = "%Y-%m-%dT%H:%M:%S.%fZ"
    else:
        timeFormat = "%Y-%m-%dT%H:%M:%S.%f%z"

    return textFileLogObserver(logfile, timeFormat=timeFormat)
