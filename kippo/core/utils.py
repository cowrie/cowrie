# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import time, anydbm
from kippo.core.config import config

def addToLastlog(message):
    db = anydbm.open('%s/lastlog.db' % \
        config().get('honeypot', 'data_path'), 'c')
    db[str(len(db)+1)] = message
    db.close()

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

# vim: set sw=4 et:
