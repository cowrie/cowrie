# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from twisted.application import internet, service
from twisted.cred import portal, checkers
from twisted.conch.ssh import factory, keys
from core import honeypot
import config

factory = honeypot.HoneyPotSSHFactory()
factory.portal = portal.Portal(honeypot.HoneyPotRealm())

pubKeyString, privKeyString = honeypot.getRSAKeys()
users = {'root': 'root'}
factory.portal.registerChecker(
    checkers.InMemoryUsernamePasswordDatabaseDontUse(**users))
factory.publicKeys = {'ssh-rsa': keys.Key.fromString(data=pubKeyString)}
factory.privateKeys = {'ssh-rsa': keys.Key.fromString(data=privKeyString)}

application = service.Application('honeypot')
service = internet.TCPServer(config.ssh_port, factory)
service.setServiceParent(application)

# vim: set ft=python sw=4 et:
