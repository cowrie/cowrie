# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import string

from zope.interface import implementer

import twisted

from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword, ISSHPrivateKey, IPluggableAuthenticationModules
from twisted.cred.error import UnauthorizedLogin, UnhandledCredentials

from twisted.internet import defer
from twisted.python import log, failure
from twisted.conch import error
from twisted.conch.ssh import keys

from kippo.core.config import config

# by Walter de Jong <walter@sara.nl>
class UserDB(object):

    def __init__(self):
        self.userdb = []
        self.load()

    def load(self):
        '''load the user db'''

        userdb_file = '%s/userdb.txt' % \
            (config().get('honeypot', 'data_path'),)

        f = open(userdb_file, 'r')
        while True:
            line = f.readline()
            if not line:
                break

            line = string.strip(line)
            if not line:
                continue

            if line.startswith( '#' ):
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

        userdb_file = '%s/userdb.txt' % \
            (config().get('honeypot', 'data_path'),)

        # Note: this is subject to races between kippo instances, but hey ...
        f = open(userdb_file, 'w')
        for (login, uid, passwd) in self.userdb:
            f.write('%s:%d:%s\n' % (login, uid, passwd))
        f.close()

    def checklogin(self, thelogin, thepasswd):
        '''check entered username/password against database'''
        '''note that it allows multiple passwords for a single username'''
        '''it also knows wildcard '*' for any password'''
        '''prepend password with ! to explicitly deny it. Denials must come before wildcards'''
        for (login, uid, passwd) in self.userdb:
            # explicitly fail on !password
            if login == thelogin and passwd == '!'+thepasswd:
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

@implementer(ICredentialsChecker)
class HoneypotPublicKeyChecker:
    """
    Checker that accepts, logs and denies public key authentication attempts
    """

    credentialInterfaces = (ISSHPrivateKey,)

    def requestAvatarId(self, credentials):
        _pubKey = keys.Key.fromString(credentials.blob)
        log.msg( 'Public Key attempt for user %s with fingerprint %s' % ( credentials.username, _pubKey.fingerprint() ) )
        return failure.Failure(error.ConchError("Incorrect signature"))

@implementer(ICredentialsChecker)
class HoneypotPasswordChecker:
    """
    Checker that accepts "keyboard-interactive" and "password"
    """

    credentialInterfaces = (IUsernamePassword, IPluggableAuthenticationModules)

    def requestAvatarId(self, credentials):
        if hasattr(credentials, 'password'):
            if self.checkUserPass(credentials.username, credentials.password):
                return defer.succeed(credentials.username)
            else:
                return defer.fail(UnauthorizedLogin())
        elif hasattr(credentials, 'pamConversion'):
            return self.checkPamUser(credentials.username,
                credentials.pamConversion)
        return defer.fail(UnhandledCredentials())

    def checkPamUser(self, username, pamConversion):
        r = pamConversion((('Password:', 1),))
        return r.addCallback(self.cbCheckPamUser, username)

    def cbCheckPamUser(self, responses, username):
        for response, zero in responses:
            if self.checkUserPass(username, response):
                return defer.succeed(username)
        return defer.fail(UnauthorizedLogin())

    def checkUserPass(self, username, password):
        if UserDB().checklogin(username, password):
            log.msg( 'login attempt [%s/%s] succeeded' % (username, password) )
            return True
        else:
            log.msg( 'login attempt [%s/%s] failed' % (username, password) )
            return False

# vim: set sw=4 et:
