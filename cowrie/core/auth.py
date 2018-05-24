# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import division, absolute_import

import re
import json
from os import path
from random import randint

from twisted.python import log

from cowrie.core.config import CONFIG

class UserDB(object):
    """
    By Walter de Jong <walter@sara.nl>
    """

    def __init__(self):
        self.userdb = {}
        self.userdb_file = '%s/userdb.txt' % CONFIG.get('honeypot', 'data_path')
        self.load()


    def load(self):
        """
        load the user db
        """

        with open(self.userdb_file, 'rb') as f:
            while True:
                rawline = f.readline()
                if not rawline:
                    break

                line = rawline.strip()
                if not line:
                    continue

                if line.startswith(b'#'):
                    continue

                login, passwd = re.split(br':\w+:', line, 1)
                self.adduser(login, passwd)


    def checklogin(self, thelogin, thepasswd, src_ip='0.0.0.0'):
        for credentials, policy in self.userdb.items():
            login, passwd = credentials

            if self.match_rule(login, thelogin):
                if self.match_rule(passwd, thepasswd):
                    return policy

        return False


    def match_rule(self, rule, input):
        if type(rule) is bytes:
            return rule in [b'*', input]
        else:
            return bool(rule.search(input))


    def re_or_str(self, rule):
        """
        Convert a /.../ type rule to a regex, otherwise return the string as-is
        """
        res = re.match(br'/(.+)/(i)?$', rule)
        if res:
            return re.compile(res.group(1), re.IGNORECASE if res.group(2) else 0)

        return rule


    def adduser(self, login, passwd):
        login = self.re_or_str(login)

        if passwd.startswith(b'!'):
            policy = False
            passwd = passwd[1:]
        else:
            policy = True

        passwd = self.re_or_str(passwd)
        self.userdb[(login, passwd)] = policy


class AuthRandom(object):
    """
    Alternative class that defines the checklogin() method.
    Users will be authenticated after a random number of attempts.
    """

    def __init__(self):
        # Default values
        self.mintry, self.maxtry, self.maxcache = 2, 5, 10

        # Are there auth_class parameters?
        if CONFIG.has_option('honeypot', 'auth_class_parameters'):
            parameters = CONFIG.get('honeypot', 'auth_class_parameters')
            parlist = parameters.split(',')
            if len(parlist) == 3:
                self.mintry = int(parlist[0])
                self.maxtry = int(parlist[1])
                self.maxcache = int(parlist[2])

        if self.maxtry < self.mintry:
            self.maxtry = self.mintry + 1
            log.msg('maxtry < mintry, adjusting maxtry to: %d' % (self.maxtry,))
        self.uservar = {}
        self.uservar_file = '%s/uservar.json' % CONFIG.get('honeypot', 'data_path')
        self.loadvars()


    def loadvars(self):
        """
        Load user vars from json file
        """
        if path.isfile(self.uservar_file):
            with open(self.uservar_file, 'rb') as fp:
                try:
                    self.uservar = json.load(fp)
                except:
                    self.uservar = {}


    def savevars(self):
        """
        Save the user vars to json file
        """
        data = self.uservar
        # Note: this is subject to races between cowrie logins
        with open(self.uservar_file, 'wb') as fp:
            json.dump(data, fp)


    def checklogin(self, thelogin, thepasswd, src_ip):
        """
        Every new source IP will have to try a random number of times between
        'mintry' and 'maxtry' before succeeding to login.
        All username/password combinations  must be different.
        The successful login combination is stored with the IP address.
        Successful username/passwords pairs are also cached for 'maxcache' times.
        This is to allow access for returns from different IP addresses.
        Variables are saved in 'uservar.json' in the data directory.
        """

        auth = False
        userpass = thelogin + ':' + thepasswd

        if not 'cache' in self.uservar:
            self.uservar['cache'] = []
        cache = self.uservar['cache']

        # Check if it is the first visit from src_ip
        if src_ip not in self.uservar:
            self.uservar[src_ip] = {}
            ipinfo = self.uservar[src_ip]
            ipinfo['try'] = 0
            if userpass in cache:
                log.msg('first time for %s, found cached: %s' % (src_ip, userpass))
                ipinfo['max'] = 1
                ipinfo['user'] = thelogin
                ipinfo['pw'] = thepasswd
                auth = True
                self.savevars()
                return auth
            else:
                ipinfo['max'] = randint(self.mintry, self.maxtry)
                log.msg('first time for %s, need: %d' % (src_ip, ipinfo['max']))

        ipinfo = self.uservar[src_ip]

        # Fill in missing variables
        if not 'max' in ipinfo:
            ipinfo['max'] = randint(self.mintry, self.maxtry)
        if not 'try' in ipinfo:
            ipinfo['try'] = 0
        if not 'tried' in ipinfo:
            ipinfo['tried'] = []

        # Don't count repeated username/password combinations
        if userpass in ipinfo['tried']:
            log.msg('already tried this combination')
            self.savevars()
            return auth

        ipinfo['try'] += 1
        attempts = ipinfo['try']
        need = ipinfo['max']
        log.msg('login attempt: %d' % (attempts,))

        # Check if enough login attempts are tried
        if attempts < need:
            self.uservar[src_ip]['tried'].append(userpass)
        elif attempts == need:
            ipinfo['user'] = thelogin
            ipinfo['pw'] = thepasswd
            cache.append(userpass)
            if len(cache) > self.maxcache:
                cache.pop(0)
            auth = True
        # Returning after successful login
        elif attempts > need:
            if not 'user' in ipinfo or not 'pw' in ipinfo:
                log.msg('return, but username or password not set!!!')
                ipinfo['tried'].append(userpass)
                ipinfo['try'] = 1
            else:
                log.msg('login return, expect: [%s/%s]' % (ipinfo['user'], ipinfo['pw']))
                if thelogin == ipinfo['user'] and thepasswd == ipinfo['pw']:
                    auth = True
        self.savevars()
        return auth

