# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import sys, os
if sys.platform == 'win32':
    import os, inspect
    # this is when just running on win32
    sys.path.insert(0, os.path.abspath(os.getcwd()))
    # and this is when running as a service
    #os.chdir(os.path.dirname(inspect.getfile(inspect.currentframe())))

from twisted.internet import reactor, defer
from twisted.application import internet, service
from twisted.cred import portal
from twisted.conch.ssh import factory, keys

if os.name == 'posix' and os.getuid() == 0:
    print 'ERROR: You must not run kippo as root!'
    sys.exit(1)

if not os.path.exists('kippo.cfg'):
    print 'ERROR: kippo.cfg is missing!'
    sys.exit(1)

from kippo.core import honeypot
from kippo.core.config import config

factory = honeypot.HoneyPotSSHFactory()
factory.portal = portal.Portal(honeypot.HoneyPotRealm())

pubKeyString, privKeyString = honeypot.getRSAKeys()
# Move this somewhere if we decide to use more passwords
users = (
    ('root', 'root'),
    ('root', '123456'),
    )
factory.portal.registerChecker(honeypot.HoneypotPasswordChecker(users))
factory.publicKeys = {'ssh-rsa': keys.Key.fromString(data=pubKeyString)}
factory.privateKeys = {'ssh-rsa': keys.Key.fromString(data=privKeyString)}

application = service.Application('honeypot')
service = internet.TCPServer(
    int(config().get('honeypot', 'ssh_port')), factory)
service.setServiceParent(application)

# vim: set ft=python sw=4 et:
