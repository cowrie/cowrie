# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import time, anydbm
from kippo.core.config import config

def addToLastlog(message):
    f = file('%s/lastlog.txt' % config().get('honeypot', 'data_path'), 'a')
    f.write('%s\n' % (message,))
    f.close()

def durationHuman(seconds):
    seconds = long(round(seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    years, days = divmod(days, 365.242199)
 
    sdays = str(days)
    syears = str(years)
    sseconds = str(seconds).rjust(2, '0')
    sminutes = str(minutes).rjust(2, '0')
    shours = str(hours).rjust(2, '0')

    duration = []
    if years > 0:
        duration.append('%s year' % syears + 's'*(years != 1) + ' ')
    else:
        if days > 0:
            duration.append('%s day' % sdays + 's'*(days != 1) + ' ')
        if hours > 0:
            duration.append('%s:' % shours)
        if minutes >= 0:
            duration.append('%s:' % sminutes)
        if seconds >= 0:
            duration.append('%s' % sseconds)

    return ''.join(duration)

# From http://stackoverflow.com/questions/136168/get-last-n-lines-of-a-file-with-python-similar-to-tail
def tail(the_file, lines_2find=20):
    the_file.seek(0, 2)                         #go to end of file
    bytes_in_file = the_file.tell()
    lines_found, total_bytes_scanned = 0, 0
    while lines_2find+1 > lines_found and bytes_in_file > total_bytes_scanned:
        byte_block = min(1024, bytes_in_file-total_bytes_scanned)
        the_file.seek(-(byte_block+total_bytes_scanned), 2)
        total_bytes_scanned += byte_block
        lines_found += the_file.read(1024).count('\n')
    the_file.seek(-total_bytes_scanned, 2)
    line_list = list(the_file.readlines())
    return line_list[-lines_2find:]
    #we read at least 21 line breaks from the bottom, block by block for speed
    #21 to ensure we don't get a half line
 
# Gives a human-readable uptime string
# Thanks to http://thesmithfam.org/blog/2005/11/19/python-uptime-script/
# (modified to look like the real uptime command)
def uptime(total_seconds):
     total_seconds = float(total_seconds)
 
     # Helper vars:
     MINUTE  = 60
     HOUR    = MINUTE * 60
     DAY     = HOUR * 24
 
     # Get the days, hours, etc:
     days    = int(total_seconds / DAY)
     hours   = int((total_seconds % DAY) / HOUR)
     minutes = int((total_seconds % HOUR) / MINUTE)
 
     # 14 days,  3:53
     # 11 min

     s = ''
     if days > 0:
         s += str(days) + " " + (days == 1 and "day" or "days" ) + ", "
     if len(s) > 0 or hours > 0:
         s += '%s:%s' % (str(hours).rjust(2), str(minutes).rjust(2, '0'))
     else:
         s += '%s min' % (str(minutes))
     return s

# vim: set sw=4 et:
