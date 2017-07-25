# -*- test-case-name: cowrie.test.utils -*-
# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


"""
Should be compatible with user mode linux
"""

from __future__ import division, absolute_import

import struct

OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3


def ttylog_open(logfile, stamp):
    """
    Initialize new tty log

    @param logfile: logfile name
    @param stamp: timestamp
    """
    with open(logfile, 'ab') as f:
        sec, usec = int(stamp), int(1000000 * (stamp - int(stamp)))
        f.write(struct.pack('<iLiiLL', 1, 0, 0, 0, sec, usec))



def ttylog_write(logfile, length, direction, stamp, data=None):
    """
    Write to tty log

    @param logfile: timestamp
    @param length: length
    @param direction: 0 or 1
    @param stamp: timestamp
    @param data: data
    """
    with open(logfile, 'ab') as f:
        sec, usec = int(stamp), int(1000000 * (stamp - int(stamp)))
        f.write(struct.pack('<iLiiLL', 3, 0, length, direction, sec, usec))
        f.write(data)



def ttylog_close(logfile, stamp):
    """
    Close tty log

    @param logfile: logfile name
    @param stamp: timestamp
    """
    with open(logfile, 'ab') as f:
        sec, usec = int(stamp), int(1000000 * (stamp - int(stamp)))
        f.write(struct.pack('<iLiiLL', 2, 0, 0, 0, sec, usec))

