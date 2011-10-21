#!/usr/bin/env python
#
# Copyright (C) 2003-2011 Upi Tamminen <desaster@dragonlight.fi>
#

import os, sys, time, struct, string, getopt

OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3

def playlog(fd, settings):

    ssize = struct.calcsize('<iLiiLL')
    currtty, prevtime, prefdir = 0, 0, 0

    color = None

    while 1:
        try:
            (op, tty, length, dir, sec, usec) = \
                struct.unpack('<iLiiLL', fd.read(ssize))
            data = fd.read(length)
        except struct.error:
            if settings['tail']:
                prevtime = 0
                time.sleep(0.1)
                settings['maxdelay'] = 0
                continue
            break
        
        if currtty == 0: currtty = tty

        if str(tty) == str(currtty) and op == OP_WRITE:
            # the first stream seen is considered 'output'
            if prefdir == 0:
                prefdir = dir
                # use the other direction
                if settings['input_only']:
                    prefdir = TYPE_INPUT
                    if dir == TYPE_INPUT: prefdir = TYPE_OUTPUT
            if dir == TYPE_INTERACT:
                color = '\033[36m'
            elif dir == TYPE_INPUT:
                color = '\033[33m'
            if dir == prefdir or settings['both_dirs']:
                curtime = float(sec) + float(usec) / 1000000
                if prevtime != 0:
                    sleeptime = curtime - prevtime
                    if sleeptime > settings['maxdelay']:
                        sleeptime = settings['maxdelay']
                    if settings['maxdelay'] > 0:
                        time.sleep(sleeptime)
                prevtime = curtime
                if settings['colorify'] and color:
                    sys.stdout.write(color)
                sys.stdout.write(data)
                if settings['colorify'] and color:
                    sys.stdout.write('\033[0m')
                    color = None
                sys.stdout.flush()
        elif str(tty) == str(currtty) and op == OP_CLOSE:
            break

def help(brief = 0):

    print 'Usage: %s [-bfhi] [-m secs] [-w file] <tty-log-file>\n' % \
        os.path.basename(sys.argv[0])

    if not brief:
        print '  -f             keep trying to read the log until it\'s closed'
        print '  -m <seconds>   maximum delay in seconds, to avoid' + \
            ' boredom or fast-forward\n' + \
            '                 to the end. (default is 3.0)'
        print '  -i             show the input stream instead of output'
        print '  -b             show both input and output streams'
        print '  -c             colorify the output stream based on what streams are being received'
        print '  -h             display this help\n'

    sys.exit(1)

if __name__ == '__main__':

    settings = {
        'tail':         0,
        'maxdelay':     3.0,
        'input_only':   0,
        'both_dirs':    0,
        'colorify':     0,
        }

    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'fhibcm:w:', ['help'])
    except getopt.GetoptError, error:
        print 'Error: %s\n' % error
        help()

    for o, a in optlist:
        if o == '-f': settings['tail'] = 1
        elif o == '-m': settings['maxdelay'] = float(a) # takes decimals
        elif o == '-i': settings['input_only'] = 1
        elif o == '-b': settings['both_dirs'] = 1
        elif o in ['-h', '--help']: help()
        elif o == '-c': settings['colorify'] = 1

    if len(args) < 1:
        help()

    try:
        logfd = open(args[0], 'rb')
    except IOError:
        print "Couldn't open log file!"
        sys.exit(2)

    playlog(logfd, settings)

# vim: set sw=4:
