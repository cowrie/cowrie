# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import sys, os
if sys.platform == 'win32':
    # this is when just running on win32
    sys.path.insert(0, os.path.abspath(os.getcwd()))
    # and this is when running as a service
    #os.chdir(os.path.dirname(inspect.getfile(inspect.currentframe())))

from twisted.application import internet, service
from twisted.cred import portal
from twisted.conch.ssh import factory, keys

if os.name == 'posix' and os.getuid() == 0:
    print 'ERROR: You must not run cowrie as root!'
    sys.exit(1)

if not os.path.exists('cowrie.cfg'):
    print 'ERROR: cowrie.cfg is missing!'
    sys.exit(1)

from cowrie.core.config import config
import cowrie.core.honeypot
import cowrie.core.ssh
from cowrie import core

factory = core.ssh.HoneyPotSSHFactory()
factory.portal = portal.Portal(core.ssh.HoneyPotRealm())

factory.portal.registerChecker(core.auth.HoneypotPublicKeyChecker())
factory.portal.registerChecker(core.auth.HoneypotPasswordChecker())

rsa_pubKeyString, rsa_privKeyString = core.ssh.getRSAKeys()
dsa_pubKeyString, dsa_privKeyString = core.ssh.getDSAKeys()
factory.publicKeys = {'ssh-rsa': keys.Key.fromString(data=rsa_pubKeyString),
                      'ssh-dss': keys.Key.fromString(data=dsa_pubKeyString)}
factory.privateKeys = {'ssh-rsa': keys.Key.fromString(data=rsa_privKeyString),
                       'ssh-dss': keys.Key.fromString(data=dsa_privKeyString)}

cfg = config()

if cfg.has_option('honeypot', 'listen_addr'):
    listen_addr = cfg.get('honeypot', 'listen_addr')
elif cfg.has_option('honeypot', 'ssh_addr'):
    # ssh_addr for backwards compatibility
    listen_addr = cfg.get('honeypot', 'ssh_addr')
else:
    listen_addr = '0.0.0.0'

if cfg.has_option('honeypot', 'listen_port'):
    listen_port = int(cfg.get('honeypot', 'listen_port'))
elif cfg.has_option('honeypot', 'ssh_port'):
    # ssh_port for backwards compatibility
    listen_port = int(cfg.get('honeypot', 'ssh_port'))
else:
    listen_port = 2222

application = service.Application('honeypot')
for i in listen_addr.split():
    service = internet.TCPServer( listen_port,
            factory, interface=i)
    service.setServiceParent(application)

if cfg.has_option('honeypot', 'interact_enabled') and \
        cfg.get('honeypot', 'interact_enabled').lower() in \
        ('yes', 'true', 'on'):
    iport = int(cfg.get('honeypot', 'interact_port'))
    from cowrie.core import interact
    service = internet.TCPServer(iport, interact.makeInteractFactory(factory))
    service.setServiceParent(application)

# vim: set ft=python sw=4 et:
