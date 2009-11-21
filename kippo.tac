# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

from twisted.application import internet, service
from twisted.cred import portal
from twisted.conch.ssh import factory, keys
from core import honeypot
import config

factory = honeypot.HoneyPotSSHFactory()
factory.portal = portal.Portal(honeypot.HoneyPotRealm())

pubKeyString, privKeyString = honeypot.getRSAKeys()
# Move this somewhere if we decide to use more passwords
users = (
    ('root', 'root'),
    ('root', '1234'),
    )
factory.portal.registerChecker(honeypot.HoneypotPasswordChecker(users))
factory.publicKeys = {'ssh-rsa': keys.Key.fromString(data=pubKeyString)}
factory.privateKeys = {'ssh-rsa': keys.Key.fromString(data=privKeyString)}

application = service.Application('honeypot')
service = internet.TCPServer(config.ssh_port, factory)
service.setServiceParent(application)

# vim: set ft=python sw=4 et:
