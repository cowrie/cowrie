#!/usr/bin/env python

from twisted.cred import portal, checkers
from twisted.conch.ssh import factory, keys
from twisted.internet import reactor
from twisted.python import log
from core import honeypot
import config

if __name__ == "__main__":
    log.startLogging(file('%s/kippo.log' % config.log_path, 'a'))

    sshFactory = honeypot.HoneyPotSSHFactory()
    sshFactory.portal = portal.Portal(honeypot.HoneyPotRealm())

    users = {'root': 'root'}
    sshFactory.portal.registerChecker(
        checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))

    pubKeyString, privKeyString = honeypot.getRSAKeys()
    sshFactory.publicKeys = {
        'ssh-rsa': keys.Key.fromString(data=pubKeyString)}
    sshFactory.privateKeys = {
        'ssh-rsa': keys.Key.fromString(data=privKeyString)}

    reactor.listenTCP(config.ssh_port, sshFactory)
    reactor.run()

# vim: set sw=4 et:
