# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import json
from os import path
from random import randint

from twisted.python import log

class UserDB(object):
    """
    By Walter de Jong <walter@sara.nl>
    """

    def __init__(self, cfg):
        self.userdb = []
        self.userdb_file = '%s/userdb.txt' % cfg.get('honeypot', 'data_path')
        self.load()


    def load(self):
        """
        load the user db
        """

        with open(self.userdb_file, 'r') as f:
            while True:
                rawline = f.readline()
                if not rawline:
                    break

                line = rawline.strip()
                if not line:
                    continue

                if line.startswith('#'):
                    continue

                (login, uid, passwd) = line.split(':', 2)

                self.userdb.append((login, passwd))


    def save(self):
        """
        save the user db
        """

        # Note: this is subject to races between cowrie instances, but hey ...
        with open(self.userdb_file, 'w') as f:
            for (login, passwd) in self.userdb:
                f.write('%s:x:%s\n' % (login, passwd))


    def checklogin(self, thelogin, thepasswd, src_ip='0.0.0.0'):
        """
        check entered username/password against database
        note that it allows multiple passwords for a single username
        it also knows wildcard '*' for any password
        prepend password with ! to explicitly deny it. Denials must come before wildcards
        """
        for (login, passwd) in self.userdb:
            # Explicitly fail on !password
            if login == thelogin and passwd == '!' + thepasswd:
                return False
            if login == thelogin and passwd in (thepasswd, '*'):
                return True
        return False


    def user_password_exists(self, thelogin, thepasswd):
        """
        """
        for (login, passwd) in self.userdb:
            if login == thelogin and passwd == thepasswd:
                return True
        return False


    def adduser(self, login, passwd):
        """
        """
        if self.user_password_exists(login, passwd):
            return
        self.userdb.append((login, passwd))
        self.save()



class AuthRandom(object):
    """
    Alternative class that defines the checklogin() method.
    Users will be authenticated after a random number of attempts.
    """

    def __init__(self, cfg):
        # Default values
        self.mintry, self.maxtry, self.maxcache = 2, 5, 10

        # Are there auth_class parameters?
        if cfg.has_option('honeypot', 'auth_class_parameters'):
            parameters = cfg.get('honeypot', 'auth_class_parameters')
            parlist = parameters.split(',')
            if len(parlist) == 3:
                self.mintry = int(parlist[0])
                self.maxtry = int(parlist[1])
                self.maxcache = int(parlist[2])

        if self.maxtry < self.mintry:
            self.maxtry = self.mintry + 1
            log.msg('maxtry < mintry, adjusting maxtry to: %d' % (self.maxtry,))
        self.uservar = {}
        self.uservar_file = '%s/uservar.json' % cfg.get('honeypot', 'data_path')
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

