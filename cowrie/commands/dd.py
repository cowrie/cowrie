import time
import re
import getopt
import random

from twisted.internet import reactor

from cowrie.core.honeypot import HoneyPotCommand

commands = {}


class command_dd(HoneyPotCommand):
    def start(self):
        try:
            opts, args = getopt.gnu_getopt(self.args, '', ['help', 'version', 'param'])
        except Exception as err:
            self.writeln("dd: invalid option");
            self.writeln("Try `dd --help' for more information")
            self.exit()
            return

            # Parse options
        for o, a in opts:
            if o in ("--version"):
                self.version()
                return
            elif o in ("--help"):
                self.help()
                return
        try:
            for arg in args:
                argument, file = arg.split("=")
                if argument == "bs":
                    bsSize= re.sub("[mMgGkKbB]","",file)
                if argument == "count":
                    countSize = re.sub("[mMgGkKbB]","",file)
            size = long(bsSize,10) * long(countSize,10)
            self.writeln(countSize + "+0 records in")
            self.writeln(countSize + "+0 records out")
            self.writeln(str(size) + " bytes transferred in 1.04276 sec (" + str(size) + " bytes/sec)")
        except Exception as err:
            self.writeln("dd: invalid option");
            self.writeln("Try `dd --help' for more information")
            self.exit()
            return

        self.exit()

    def version(self):
        self.write("""dd (coreutils) 8.13
Copyright (C) 2011 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Paul Rubin, David MacKenzie, and Stuart Kemp.
""")
        self.exit()

    def help(self):
        self.write("""'Usage: dd [OPERAND]...
or:  dd OPTION
Copy a file, converting and formatting according to the operands.

bs=BYTES        read and write up to BYTES bytes at a time
cbs=BYTES       convert BYTES bytes at a time
conv=CONVS      convert the file as per the comma separated symbol list
count=BLOCKS    copy only BLOCKS input blocks
ibs=BYTES       read up to BYTES bytes at a time (default: 512)
if=FILE         read from FILE instead of stdin
iflag=FLAGS     read as per the comma separated symbol list
obs=BYTES       write BYTES bytes at a time (default: 512)
of=FILE         write to FILE instead of stdout
oflag=FLAGS     write as per the comma separated symbol list
seek=BLOCKS     skip BLOCKS obs-sized blocks at start of output
skip=BLOCKS     skip BLOCKS ibs-sized blocks at start of input
status=noxfer   suppress transfer statistics

BLOCKS and BYTES may be followed by the following multiplicative suffixes:
c =1, w =2, b =512, kB =1000, K =1024, MB =1000*1000, M =1024*1024, xM =M
GB =1000*1000*1000, G =1024*1024*1024, and so on for T, P, E, Z, Y.

Each CONV symbol may be:

ascii     from EBCDIC to ASCII
ebcdic    from ASCII to EBCDIC
ibm       from ASCII to alternate EBCDIC
block     pad newline-terminated records with spaces to cbs-size
unblock   replace trailing spaces in cbs-size records with newline
    lcase     change upper case to lower case
ucase     change lower case to upper case
swab      swap every pair of input bytes
sync      pad every input block with NULs to ibs-size; when used
with block or unblock, pad with spaces rather than NULs
excl      fail if the output file already exists
nocreat   do not create the output file
notrunc   do not truncate the output file
noerror   continue after read errors
fdatasync  physically write output file data before finishing
fsync     likewise, but also write metadata

Each FLAG symbol may be:

append    append mode (makes sense only for output; conv=notrunc suggested)
direct    use direct I/O for data
    directory  fail unless a directory
dsync     use synchronized I/O for data
    sync      likewise, but also for metadata
    fullblock  accumulate full blocks of input (iflag only)
nonblock  use non-blocking I/O
noatime   do not update access time
nocache   discard cached data
noctty    do not assign controlling terminal from file
nofollow  do not follow symlinks

Sending a USR1 signal to a running `dd' process makes it
print I/O statistics to standard error and then resume copying.

$ dd if=/dev/zero of=/dev/null& pid=$!
$ kill -USR1 $pid; sleep 1; kill $pid
18335302+0 records in
18335302+0 records out
9387674624 bytes (9.4 GB) copied, 34.6279 seconds, 271 MB/s

Options are:

--help     display this help and exit
--version  output version information and exit

Report dd bugs to bug-coreutils@gnu.org
GNU coreutils home page: <http://www.gnu.org/software/coreutils/>
General help using GNU software: <http://www.gnu.org/gethelp/>
Report dd translation bugs to <http://translationproject.org/team/>
For complete documentation, run: info coreutils 'dd invocation'
""")
        self.exit()


commands['/bin/dd'] = command_dd
