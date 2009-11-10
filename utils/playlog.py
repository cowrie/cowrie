#!/usr/bin/env python
#
# Copyright (C) 2003  Upi Tamminen <desaster@dragonlight.fi>
#
# Last update: Mon Sep 15 20:01:15 EEST 2003
# * Sessions can now be extracted to a file
# * The first data seen is considered 'output'.
#   If this guess is wrong, the new -i option can be used
# * Rewritten to use file positions instead of tty IDs
# * Added -f that works like tail -f
# * Delays longer than 5 seconds are shortened to 5 seconds
#

import os, sys, time, struct, string, getopt, fcntl, termios

OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
DIR_READ, DIR_WRITE = 1, 2

def termwidth():
    return struct.unpack("hhhh",
        fcntl.ioctl(0, termios.TIOCGWINSZ ,"\000" * 8))[1]


def maxcolumnlen(list, column):
    maxlen = 0
    for row in list:
        if len(row[column]) > maxlen:
            maxlen = len(row[column])
    return maxlen


def playlog(fd, pos, settings):

    ssize = struct.calcsize('iLiiLL')
    currtty, prevtime, prefdir = 0, 0, 0

    fd.seek(int(pos))

    while 1:
        try:
            (op, tty, length, dir, sec, usec) = \
                struct.unpack('iLiiLL', fd.read(ssize))
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
                    prefdir = DIR_READ
                    if dir == DIR_READ: prefdir = DIR_WRITE
            if dir == prefdir or settings['both_dirs']:
                curtime = float(sec) + float(usec) / 1000000
                if prevtime != 0:
                    sleeptime = curtime - prevtime
                    if sleeptime > settings['maxdelay']:
                        sleeptime = settings['maxdelay']
                    if settings['maxdelay'] > 0:
                        time.sleep(sleeptime)
                prevtime = curtime
                sys.stdout.write(data)
                sys.stdout.flush()
        elif str(tty) == str(currtty) and op == OP_CLOSE:
            break


def writelog(fd, outfile, pos):

    ssize = struct.calcsize('iLiiLL')
    currtty, prevtime, prefdir = 0, 0, 0

    try:
        outfd = open(outfile, 'ab')
    except IOError:
        print "Couldn't open the output file!"
        sys.exit(3)

    fd.seek(int(pos))

    written = 0
    while 1:
        try:
            structdata = fd.read(ssize)
            op, tty, length, dir, sec, usec = \
                struct.unpack('iLiiLL', structdata)
            data = fd.read(length)
        except struct.error:
            op = -1
        
        if currtty == 0: currtty = tty

        if str(tty) == str(currtty):
            outfd.write(structdata + data)
            written += len(structdata + data)
        if op == OP_CLOSE or op == -1:
            print 'Total %d bytes written' % written
            break


def showsessions(fd):

    ssize = struct.calcsize('iLiiLL')
    ttys, chunches, currpos = {}, [], 0

    # no point in reading more...
    maxglancelen = termwidth()

    while 1:
        try:
            structdata = fd.read(ssize)
            op, tty, length, dir, sec, usec = \
                struct.unpack('iLiiLL', structdata)
            data = fd.read(length)
        except struct.error:
            op = -1

        if op == OP_OPEN:
            ttys[tty] = {
                'pos':          currpos,
                'start':        sec,
                'end':          sec,
                'size':         0,
                'glance':       '',
                'prefdir':      0,
                }
        elif op == OP_CLOSE or op == -1:
            if ttys.has_key(tty):
                chunch = ttys[tty]
                chunch['end'] = sec
                chunches.append(chunch)
		del ttys[tty]
        elif op == OP_WRITE:
            if ttys[tty]['prefdir'] == 0:
                ttys[tty]['prefdir'] = dir
            if dir == ttys[tty]['prefdir']:
                ttys[tty]['size'] += len(data)
                if len(ttys[tty]['glance']) <= maxglancelen:
                    ttys[tty]['glance'] += data

	if op == -1:
	    break

        currpos += len(structdata) + length

    # unclosed sessions
    for tty in ttys.keys():
        chunch = ttys[tty]
        chunch['end'] = -1
	chunches.append(chunch)

    sessions = [['id', 'start', 'end', 'size', 'glance']]

    for chunch in chunches:

        session = [str(chunch['pos'])]

        startdate = time.localtime(chunch['start'])
        enddate = time.localtime(chunch['end'])

        session.append(time.strftime('%Y-%m-%d %R', startdate))
        if chunch['end'] == -1:
            session.append('still open')
        else:
            if time.strftime('%Y-%m-%d', enddate) == \
                    time.strftime('%Y-%m-%d', startdate):
                session.append(time.strftime('%R', enddate))
            else:
                session.append(time.strftime('%Y-%m-%d %R', enddate))

        session.append('%s' % chunch['size'])
        session.append(chunch['glance'].translate(
            string.maketrans('\t\n\r\x1b', '    ')).strip())

        sessions.append(session)

    maxidlen = maxcolumnlen(sessions, 0) + 1
    maxstartdatelen = maxcolumnlen(sessions, 1) + 1
    maxenddatelen = maxcolumnlen(sessions, 2) + 1
    maxcounterlen = maxcolumnlen(sessions, 3) + 1
    spaceleft = termwidth() - \
        (maxidlen + maxstartdatelen + maxenddatelen + maxcounterlen + 5)

    for session in sessions:
        print '%s %s %s %s %s' % (session[0].ljust(maxidlen),
            session[1].ljust(maxstartdatelen),
            session[2].ljust(maxenddatelen),
            session[3].ljust(maxcounterlen),
            session[4][:spaceleft])

    print
    help(brief = 1)

def help(brief = 0):

    print 'Usage: %s [-bfhi] [-m secs] [-w file] <tty-log-file> [id]\n' % \
        os.path.basename(sys.argv[0])

    if not brief:

        print '  -f             keep trying to read the log until it\'s closed'
        print '  -m <seconds>   maximum delay in seconds, to avoid' + \
            ' boredom or fast-forward\n' + \
            '                 to the end. (default is 3.0)'
        print '  -i             show the input stream instead of output'
        print '  -b             show both input and output streams'
        print '  -w <file>      extract the session to a file'
        print '  -h             display this help\n'

    sys.exit(1)

if __name__ == '__main__':

    settings = {
        'tail':         0,
        'maxdelay':     3.0,
        'input_only':   0,
        'both_dirs':    0,
        'outfile':      '',
        }

    try:
        optlist, args = getopt.getopt(sys.argv[1:], 'fhibm:w:', ['help'])
    except getopt.GetoptError, error:
        print 'Error: %s\n' % error
        help()

    for o, a in optlist:
        if o == '-f': settings['tail'] = 1
        elif o == '-m': settings['maxdelay'] = float(a) # takes decimals
        elif o == '-i': settings['input_only'] = 1
        elif o == '-b': settings['both_dirs'] = 1
        elif o == '-w': settings['outfile'] = a
        elif o in ['-h', '--help']: help()

    if len(args) < 1: help()

    try:
        logfd = open(args[0], 'rb')
    except IOError:
        print "Couldn't open log file!"
        sys.exit(2)

    if len(args) > 1:
        if len(settings['outfile']):
            writelog(logfd, settings['outfile'], args[1])
        else:
            playlog(logfd, args[1], settings)
    else:
        showsessions(logfd)


# vim: set sw=4:
