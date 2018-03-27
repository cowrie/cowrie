# -*- test-case-name: cowrie.test.utils -*-
# Copyright (c) 2017 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains
"""

from __future__ import division, absolute_import

from twisted.logger import textFileLogObserver
from twisted.python import logfile

from cowrie.core.config import CONFIG


class CowrieDailyLogFile(logfile.DailyLogFile):
    """
    Overload original Twisted with improved date formatting
    """

    def suffix(self, tupledate):
        """
        Return the suffix given a (year, month, day) tuple or unixtime
        """
        try:
            return "{:02d}-{:02d}-{:02d}".format(tupledate[0], tupledate[1], tupledate[2])
        except:
            # try taking a float unixtime
            return '_'.join(map(str, self.toDate(tupledate)))

def logger():
    """
    """
    try:
        dir = CONFIG.get("honeypot", "log_path")
    except:
        dir = "log"

    logfile = CowrieDailyLogFile("cowrie.log", dir)
    return textFileLogObserver(logfile, timeFormat='%Y-%m-%dT%H:%M:%S.%f%z')

