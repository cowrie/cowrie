#!/usr/bin/env python
#
# Copyright (C) 2003-2011 Upi Tamminen <desaster@dragonlight.fi>
#

import getopt
import os
import struct
import sys
import time

OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3


def playlog(fd, settings):
    ssize = struct.calcsize("<iLiiLL")
    currtty, prevtime, prefdir = 0, 0, 0

    color = None

    stdout = sys.stdout.buffer

    while 1:
        try:
            (op, tty, length, direction, sec, usec) = struct.unpack(
                "<iLiiLL", fd.read(ssize)
            )
            data = fd.read(length)
        except struct.error:
            if settings["tail"]:
                prevtime = 0
                time.sleep(0.1)
                settings["maxdelay"] = 0
                continue
            break

        if currtty == 0:
            currtty = tty

        if str(tty) == str(currtty) and op == OP_WRITE:
            # the first stream seen is considered 'output'
            if prefdir == 0:
                prefdir = direction
                # use the other direction
                if settings["input_only"]:
                    prefdir = TYPE_INPUT
                    if direction == TYPE_INPUT:
                        prefdir = TYPE_OUTPUT
            if direction == TYPE_INTERACT:
                color = b"\033[36m"
            elif direction == TYPE_INPUT:
                color = b"\033[33m"
            if direction == prefdir or settings["both_dirs"]:
                curtime = float(sec) + float(usec) / 1000000
                if prevtime != 0:
                    sleeptime = curtime - prevtime
                    if sleeptime > settings["maxdelay"]:
                        sleeptime = settings["maxdelay"]
                    if settings["maxdelay"] > 0:
                        time.sleep(sleeptime)
                prevtime = curtime
                if settings["colorify"] and color:
                    stdout.write(color)
                stdout.write(data)
                if settings["colorify"] and color:
                    stdout.write(b"\033[0m")
                    color = None
                sys.stdout.flush()
        elif str(tty) == str(currtty) and op == OP_CLOSE:
            break


def printhelp(brief=0):
    print(
        f"Usage: {os.path.basename(sys.argv[0])} [-bfhi] [-m secs] [-w file] <tty-log-file> <tty-log-file>...\n"
    )

    if not brief:
        print("  -f             keep trying to read the log until it's closed")
        print(
            "  -m <seconds>   maximum delay in seconds, to avoid"
            + " boredom or fast-forward\n"
            + "                 to the end. (default is 3.0)"
        )
        print("  -i             show the input stream instead of output")
        print("  -b             show both input and output streams")
        print(
            "  -c             colorify the output stream based on what streams are being received"
        )
        print("  -h             display this help\n")

    sys.exit(1)


def run():
    settings = {
        "tail": 0,
        "maxdelay": 3.0,
        "input_only": 0,
        "both_dirs": 0,
        "colorify": 0,
    }

    try:
        optlist, args = getopt.getopt(sys.argv[1:], "fhibcm:w:", ["help"])
    except getopt.GetoptError as error:
        print(f"Error: {error}\n")
        printhelp()
        return

    options = [x[0] for x in optlist]
    if "-b" in options and "-i" in options:
        print("Error: -i and -b cannot be used together. Please select only one flag")
        sys.exit(1)

    for o, a in optlist:
        if o == "-f":
            settings["tail"] = 1
        elif o == "-m":
            settings["maxdelay"] = float(a)  # takes decimals
        elif o == "-i":
            settings["input_only"] = 1
        elif o == "-b":
            settings["both_dirs"] = 1
        elif o in ["-h", "--help"]:
            printhelp()
        elif o == "-c":
            settings["colorify"] = 1

    if len(args) < 1:
        printhelp()

    for logfile in args:
        try:
            with open(logfile, "rb") as f:
                playlog(f, settings)
        except OSError:
            print(f"\n[!] Couldn't open log file {logfile}!")


if __name__ == "__main__":
    run()
