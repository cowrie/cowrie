# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import annotations

from sys import modules

from zope.interface import implementer

from twisted.conch import error
from twisted.conch.ssh import keys
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import ISSHPrivateKey
from twisted.cred.error import UnauthorizedLogin, UnhandledCredentials
from twisted.internet import defer
from twisted.python import failure, log

from cowrie.core import auth
from cowrie.core import credentials as conchcredentials
from cowrie.core.config import CowrieConfig


@implementer(ICredentialsChecker)
class HoneypotPublicKeyChecker:
    """
    Checker that accepts, logs and denies public key authentication attempts
    """

    credentialInterfaces = (ISSHPrivateKey,)

    def requestAvatarId(self, credentials):
        _pubKey = keys.Key.fromString(credentials.blob)
        log.msg(
            eventid="cowrie.client.fingerprint",
            format="public key attempt for user %(username)s of type %(type)s with fingerprint %(fingerprint)s",
            username=credentials.username,
            fingerprint=_pubKey.fingerprint(),
            key=_pubKey.toString("OPENSSH"),
            type=_pubKey.sshType(),
        )

        return failure.Failure(error.ConchError("Incorrect signature"))


@implementer(ICredentialsChecker)
class HoneypotNoneChecker:
    """
    Checker that does no authentication check
    """

    credentialInterfaces = (conchcredentials.IUsername,)

    def requestAvatarId(self, credentials):
        return defer.succeed(credentials.username)


@implementer(ICredentialsChecker)
class HoneypotPasswordChecker:
    """
    Checker that accepts "keyboard-interactive" and "password"
    """

    credentialInterfaces = (
        conchcredentials.IUsernamePasswordIP,
        conchcredentials.IPluggableAuthenticationModulesIP,
    )

    def requestAvatarId(self, credentials):
        if hasattr(credentials, "password"):
            if self.checkUserPass(
                credentials.username, credentials.password, credentials.ip
            ):
                return defer.succeed(credentials.username)
            return defer.fail(UnauthorizedLogin())
        if hasattr(credentials, "pamConversion"):
            return self.checkPamUser(
                credentials.username, credentials.pamConversion, credentials.ip
            )
        return defer.fail(UnhandledCredentials())

    def checkPamUser(self, username, pamConversion, ip):
        r = pamConversion((("Password:", 1),))
        return r.addCallback(self.cbCheckPamUser, username, ip)

    def cbCheckPamUser(self, responses, username, ip):
        for response, _ in responses:
            if self.checkUserPass(username, response, ip):
                return defer.succeed(username)
        return defer.fail(UnauthorizedLogin())

    def checkUserPass(self, theusername: bytes, thepassword: bytes, ip: str) -> bool:
        # UserDB is the default auth_class
        authname = auth.UserDB

        # Is the auth_class defined in the config file?
        if CowrieConfig.has_option("honeypot", "auth_class"):
            authclass = CowrieConfig.get("honeypot", "auth_class")
            authmodule = "cowrie.core.auth"

            # Check if authclass exists in this module
            if hasattr(modules[authmodule], authclass):
                authname = getattr(modules[authmodule], authclass)
            else:
                log.msg(f"auth_class: {authclass} not found in {authmodule}")

        theauth = authname()

        if theauth.checklogin(theusername, thepassword, ip):
            log.msg(
                eventid="cowrie.login.success",
                format="login attempt [%(username)s/%(password)s] succeeded",
                username=theusername,
                password=thepassword,
            )
            return True

        log.msg(
            eventid="cowrie.login.failed",
            format="login attempt [%(username)s/%(password)s] failed",
            username=theusername,
            password=thepassword,
        )
        return False
