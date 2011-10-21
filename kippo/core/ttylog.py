# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

# Should be compatible with user mode linux

import struct, sys

OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3

def ttylog_write(logfile, len, direction, stamp, data = None):
    f = file(logfile, 'ab')
    sec, usec = int(stamp), int(1000000 * (stamp - int(stamp)))
    f.write(struct.pack('<iLiiLL', 3, 0, len, direction, sec, usec))
    f.write(data)
    f.close()

def ttylog_open(logfile, stamp):
    f = file(logfile, 'ab')
    sec, usec = int(stamp), int(1000000 * (stamp - int(stamp)))
    f.write(struct.pack('<iLiiLL', 1, 0, 0, 0, sec, usec))
    f.close()

def ttylog_close(logfile, stamp):
    f = file(logfile, 'ab')
    sec, usec = int(stamp), int(1000000 * (stamp - int(stamp)))
    f.write(struct.pack('<iLiiLL', 2, 0, 0, 0, sec, usec))
    f.close()

# vim: set sw=4 et:
