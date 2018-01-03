# -*- test-case-name: cowrie.test.utils -*-
# Copyright (c) 2017 Michel Oosterhof <michel@oosterhof.net>
# See the COPYRIGHT file for more information

"""
This module contains 
"""

from __future__ import division, absolute_import

import os
import glob
import time
import stat

from twisted.python import logfile


class CowrieDailyLogFile(logfile.DailyLogFile):

    
    def suffix(self, tupledate):
        """
        Return the suffix given a (year, month, day) tuple or unixtime
        Overload original Twisted with improved date formatting
        """
        try:
            return "{:02d}-{:02d}-{:02d}".format(tupledate[0], tupledate[1], tupledate[2])
        except:
            # try taking a float unixtime
            return '_'.join(map(str, self.toDate(tupledate)))

