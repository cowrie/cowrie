# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import os

from twisted.conch.ssh import keys
from twisted.python import log


def getRSAKeys(cfg):
    """
    """
    publicKeyFile = cfg.get('honeypot', 'rsa_public_key')
    privateKeyFile = cfg.get('honeypot', 'rsa_private_key')
    if not (os.path.exists(publicKeyFile) and os.path.exists(privateKeyFile)):
        log.msg("Generating new RSA keypair...")
        from Crypto.PublicKey import RSA
        from twisted.python import randbytes
        KEY_LENGTH = 2048
        rsaKey = RSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(rsaKey).public().toString('openssh')
        privateKeyString = keys.Key(rsaKey).toString('openssh')
        with open(publicKeyFile, 'w+b') as f:
            f.write(publicKeyString)
        with open(privateKeyFile, 'w+b') as f:
            f.write(privateKeyString)
    else:
        with open(publicKeyFile, 'r') as f:
            publicKeyString = f.read()
        with open(privateKeyFile, 'r') as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString



def getDSAKeys(cfg):
    """
    """
    publicKeyFile = cfg.get('honeypot', 'dsa_public_key')
    privateKeyFile = cfg.get('honeypot', 'dsa_private_key')
    if not (os.path.exists(publicKeyFile) and os.path.exists(privateKeyFile)):
        log.msg("Generating new DSA keypair...")
        from Crypto.PublicKey import DSA
        from twisted.python import randbytes
        KEY_LENGTH = 1024
        dsaKey = DSA.generate(KEY_LENGTH, randbytes.secureRandom)
        publicKeyString = keys.Key(dsaKey).public().toString('openssh')
        privateKeyString = keys.Key(dsaKey).toString('openssh')
        with open(publicKeyFile, 'w+b') as f:
            f.write(publicKeyString)
        with open(privateKeyFile, 'w+b') as f:
            f.write(privateKeyString)
    else:
        with open(publicKeyFile, 'r') as f:
            publicKeyString = f.read()
        with open(privateKeyFile, 'r') as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString

