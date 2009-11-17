#!/usr/bin/env python

from twisted.cred import portal, checkers
from twisted.conch.ssh import factory, keys
from twisted.internet import reactor
from twisted.python import log
from core import Kippo
import config

if __name__ == "__main__":
    log.startLogging(file('./log/kippo.log', 'a'))

    sshFactory = Kippo.HoneyPotSSHFactory()
    sshFactory.portal = portal.Portal(Kippo.HoneyPotRealm())

    users = {'root': 'root'}
    sshFactory.portal.registerChecker(
        checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))

    pubKeyString, privKeyString = Kippo.getRSAKeys()
    sshFactory.publicKeys = {
        'ssh-rsa': keys.Key.fromString(data=pubKeyString)}
    sshFactory.privateKeys = {
        'ssh-rsa': keys.Key.fromString(data=privKeyString)}

    reactor.listenTCP(config.ssh_port, sshFactory)
    reactor.run()

# vim: set sw=4 et:
