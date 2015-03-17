# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import string
import json
from os import path
from random import randint

from zope.interface import implementer

import twisted

from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword, ISSHPrivateKey, \
    IPluggableAuthenticationModules, ICredentials
from twisted.cred.error import UnauthorizedLogin, UnhandledCredentials

from twisted.internet import defer
from twisted.python import log, failure
from twisted.conch import error
from twisted.conch.ssh import keys

from config import config

# by Walter de Jong <walter@sara.nl>
class UserDB(object):

    def __init__(self):
        self.userdb = []
        self.load()

    def load(self):
        '''load the user db'''

        userdb_file = '%s/userdb.txt' % (config().get('honeypot', 'data_path'),)

        f = open(userdb_file, 'r')
        while True:
            line = f.readline()
            if not line:
                break

            line = string.strip(line)
            if not line:
                continue

            if line.startswith('#'):
                continue

            (login, uid_str, passwd) = line.split(':', 2)

            uid = 0
            try:
                uid = int(uid_str)
            except ValueError:
                uid = 1001

            self.userdb.append((login, uid, passwd))

        f.close()

    def save(self):
        '''save the user db'''

        userdb_file = '%s/userdb.txt' % (config().get('honeypot', 'data_path'),)

        # Note: this is subject to races between kippo instances, but hey ...
        f = open(userdb_file, 'w')
        for (login, uid, passwd) in self.userdb:
            f.write('%s:%d:%s\n' % (login, uid, passwd))
        f.close()

    def checklogin(self, thelogin, thepasswd, src_ip = '0.0.0.0'):
        '''check entered username/password against database'''
        '''note that it allows multiple passwords for a single username'''
        '''it also knows wildcard '*' for any password'''
        '''prepend password with ! to explicitly deny it. Denials must come before wildcards'''
        for (login, uid, passwd) in self.userdb:
            # explicitly fail on !password
            if login == thelogin and passwd == '!' + thepasswd:
                return False
            if login == thelogin and passwd in (thepasswd, '*'):
                return True
        return False

    def user_exists(self, thelogin):
        for (login, uid, passwd) in self.userdb:
            if login == thelogin:
                return True
        return False

    def user_password_exists(self, thelogin, thepasswd):
        for (login, uid, passwd) in self.userdb:
            if login == thelogin and passwd == thepasswd:
                return True
        return False

    def getUID(self, loginname):
        for (login, uid, passwd) in self.userdb:
            if loginname == login:
                return uid
        return 1001

    def allocUID(self):
        '''allocate the next UID'''

        min_uid = 0
        for (login, uid, passwd) in self.userdb:
            if uid > min_uid:
                min_uid = uid
        return min_uid + 1

    def adduser(self, login, uid, passwd):
        if self.user_password_exists(login, passwd):
            return
        self.userdb.append((login, uid, passwd))
        self.save()

class AuthRandom(object):
    """
    Alternative class that defines the checklogin() method.
    Users will be authenticated after a random number of attempts.
    """

    def __init__(self, mintry = 2, maxtry = 5, maxcache = 10):
        self.mintry, self.maxtry, self.maxcache = mintry, maxtry, maxcache
        self.uservar = {}
        self.loadvars()

    def loadvars(self):
        # load user vars from json file
        uservar_file = '%s/uservar.json' % (config().get('honeypot', 'data_path'))
        if path.isfile(uservar_file):
            with open(uservar_file, 'rb') as fp:
                try:
                    self.uservar = json.load(fp)
                except:
                    self.uservar = {}

    def savevars(self):
        # save the user vars to json file
        uservar_file = '%s/uservar.json' % (config().get('honeypot', 'data_path'))
        data = self.uservar
        # Note: this is subject to races between kippo logins
        with open(uservar_file, 'wb') as fp:
            json.dump(data, fp)

    def checklogin(self, thelogin, thepasswd, src_ip):
        '''Every new source IP will have to try a random number of times between mintry'''
        '''and maxtry before succeeding to login'''
        '''All username/password combinations  must be different'''
        '''The successful login combination is stored with the IP address'''
        '''Successful username/passwords combo's are also cached for maxcache times'''
        '''This is to allow access for returns from different IP addresses'''
        '''Variables are saved in the uservar.json in the data directory'''
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
                log.msg('First time for %s, found cached: %s' % (src_ip, userpass))
                ipinfo['max'] = 1
                ipinfo['user'] = thelogin
                ipinfo['pw'] = thepasswd
                auth = True
                self.savevars()
                return auth
            else:
                ipinfo['max'] = randint(self.mintry, self.maxtry)
                log.msg('First time for %s, need: %d' % (src_ip, ipinfo['max']))

        ipinfo = self.uservar[src_ip]

        # Fill in missing variables
        if not 'max' in ipinfo:
            ipinfo['max'] = randint(self.mintry, self.maxtry)
        if not 'try' in ipinfo:
            ipinfo['try'] = 0
        if not 'tried' in ipinfo:
            ipinfo['tried'] = []

        # Don't count repeated username/password combo's
        if userpass in ipinfo['tried']:
            log.msg('Already tried this combo')
            self.savevars()
            return auth

        ipinfo['try'] += 1
        attempts = ipinfo['try']
        need = ipinfo['max']
        log.msg('Login attempt: %d' % attempts)

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
                log.msg('Return, but username or password not set!!!')
                ipinfo['tried'].append(userpass)
                ipinfo['try'] = 1
            else:
                log.msg('Login return, expect: [%s/%s]' % (ipinfo['user'], ipinfo['pw']))
                if thelogin == ipinfo['user'] and thepasswd == ipinfo['pw']:
                    auth = True
        self.savevars()
        return auth

@implementer(ICredentialsChecker)
class HoneypotPublicKeyChecker:
    """
    Checker that accepts, logs and denies public key authentication attempts
    """

    credentialInterfaces = (ISSHPrivateKey,)

    def requestAvatarId(self, credentials):
        _pubKey = keys.Key.fromString(credentials.blob)
        log.msg(format='public key attempt for user %(username)s with fingerprint %(fingerprint)s',
                username=credentials.username,
                fingerprint=_pubKey.fingerprint())
        return failure.Failure(error.ConchError('Incorrect signature'))

# This credential interface also provides an IP address
@implementer(IUsernamePassword)
class UsernamePasswordIP:

    def __init__(self, username, password, ip):
        self.username = username
        self.password = password
        self.ip = ip

# This credential interface also provides an IP address
@implementer(IPluggableAuthenticationModules)
class PluggableAuthenticationModulesIP:

    def __init__(self, username, pamConversion, ip):
        self.username = username
        self.pamConversion = pamConversion
        self.ip = ip

@implementer(ICredentialsChecker)
class HoneypotPasswordChecker:
    """
    Checker that accepts "keyboard-interactive" and "password"
    """

    credentialInterfaces = (IUsernamePassword, IPluggableAuthenticationModules)

    def requestAvatarId(self, credentials):
        if hasattr(credentials, 'password'):
            if self.checkUserPass(credentials.username, credentials.password,
                                  credentials.ip):
                return defer.succeed(credentials.username)
            else:
                return defer.fail(UnauthorizedLogin())
        elif hasattr(credentials, 'pamConversion'):
            return self.checkPamUser(credentials.username,
                                     credentials.pamConversion, credentials.ip)
        return defer.fail(UnhandledCredentials())

    def checkPamUser(self, username, pamConversion, ip):
        r = pamConversion((('Password:', 1),))
        return r.addCallback(self.cbCheckPamUser, username, ip)

    def cbCheckPamUser(self, responses, username, ip):
        for (response, zero) in responses:
            if self.checkUserPass(username, response, ip):
                return defer.succeed(username)
        return defer.fail(UnauthorizedLogin())

    def checkUserPass(self, theusername, thepassword, ip):
        authname=UserDB

        if config().has_option('honeypot', 'auth_class'):
            authclass = config().get('honeypot', 'auth_class')
            if authclass == 'AuthRandom':
                authname = AuthRandom

        if config().has_option('honeypot', 'auth_class_parameters'):
            parameters = config().get('honeypot', 'auth_class_parameters')
            mintry, maxtry, maxcache  = parameters.split(',')
            theauth = authname(int(mintry), int(maxtry), int(maxcache))
        else:
            theauth = authname()

        if theauth.checklogin(theusername, thepassword, ip):
            # log.msg( 'login attempt [%s/%s] succeeded' % (theusername, thepassword) )
            log.msg(eventid='KIPP0002',
                format='login attempt [%(username)s/%(password)s] succeeded',
                username=theusername, password=thepassword)
            return True
        else:
            # log.msg( 'login attempt [%s/%s] failed' % (theusername, thepassword) )
            log.msg(eventid='KIPP0003',
                format='login attempt [%(username)s/%(password)s] failed',
                username=theusername, password=thepassword)
            return False

# vim: set sw=4 et:
