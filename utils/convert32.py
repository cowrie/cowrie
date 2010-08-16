#!/usr/bin/env python
#
# Convert tty logs to a standard 32-bit little-endian format
#
# Example of usage:
#
#    ./convert64.py < input.log > output.log
#
# Before doing anything, backing up your old logs is a good idea!

import sys, struct

if __name__ == '__main__':
    ssize = struct.calcsize('iLiiLL')
    while 1:
        try:
            (op, tty, length, dir, sec, usec) = \
                struct.unpack('iLiiLL', sys.stdin.read(ssize))
            data = sys.stdin.read(length)
        except struct.error:
            break
        sys.stdout.write(struct.pack('<iLiiLL',
            op, tty, length, dir, sec, usec))
        sys.stdout.write(data)

# vim: set sw=4 et:
