# -*- test-case-name: cowrie.test.utils -*-
# Copyright (c) 2017 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information


from __future__ import annotations

from os import environ
from pathlib import Path

from twisted.logger import textFileLogObserver
from twisted.python import logfile

from cowrie.core.config import CowrieConfig


class CowrieDailyLogFile(logfile.DailyLogFile):
    """
    Overload original Twisted with improved date formatting
    """

    def suffix(self, tupledate: float | tuple[int, int, int]) -> str:
        """
        Return the suffix given a (year, month, day) tuple or unixtime
        """
        if isinstance(tupledate, tuple):
            return f"{tupledate[0]:02d}-{tupledate[1]:02d}-{tupledate[2]:02d}"
        if isinstance(tupledate, float):
            return "_".join(map(str, self.toDate(tupledate)))
        raise TypeError


def logger():
    """
    Custom logger that can log in a defined timezone and with custom
    roll over properties
    """
    directory = CowrieConfig.get("honeypot", "log_path", fallback=".")

    logtype = CowrieConfig.get("honeypot", "logtype", fallback="plain")
    if logtype == "rotating":
        cowrielog = CowrieDailyLogFile("cowrie.log", directory)
    elif logtype == "plain":
        cowrielog = open(Path(directory, "plain.log"), "w", encoding="utf-8")
    else:
        raise ValueError

    # use Z for UTC (Zulu) time, it's shorter.
    if "TZ" in environ and environ["TZ"] == "UTC":
        timeFormat = "%Y-%m-%dT%H:%M:%S.%fZ"
    else:
        timeFormat = "%Y-%m-%dT%H:%M:%S.%f%z"

    return textFileLogObserver(cowrielog, timeFormat=timeFormat)
