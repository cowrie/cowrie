# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import annotations

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from twisted.conch.ssh import keys
from twisted.python import log

from cowrie.core.config import CowrieConfig


def getRSAKeys() -> tuple[bytes, bytes]:
    publicKeyFile: str = CowrieConfig.get(
        "ssh", "rsa_public_key", fallback="ssh_host_rsa_key.pub"
    )
    privateKeyFile: str = CowrieConfig.get(
        "ssh", "rsa_private_key", fallback="ssh_host_rsa_key"
    )
    if not (os.path.exists(publicKeyFile) and os.path.exists(privateKeyFile)):
        log.msg("Generating new RSA keypair...")

        rsaKey = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        publicKeyString = keys.Key(rsaKey).public().toString("openssh")
        privateKeyString = keys.Key(rsaKey).toString("openssh")
        with open(publicKeyFile, "w+b") as f:
            f.write(publicKeyString)
        with open(privateKeyFile, "w+b") as f:
            f.write(privateKeyString)
    else:
        with open(publicKeyFile, "rb") as f:
            publicKeyString = f.read()
        with open(privateKeyFile, "rb") as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString


def getDSAKeys() -> tuple[bytes, bytes]:
    publicKeyFile: str = CowrieConfig.get(
        "ssh", "dsa_public_key", fallback="ssh_host_dsa_key.pub"
    )
    privateKeyFile: str = CowrieConfig.get(
        "ssh", "dsa_private_key", fallback="ssh_host_dsa_key"
    )
    if not (os.path.exists(publicKeyFile) and os.path.exists(privateKeyFile)):
        log.msg("Generating new DSA keypair...")

        dsaKey = dsa.generate_private_key(key_size=1024, backend=default_backend())
        publicKeyString = keys.Key(dsaKey).public().toString("openssh")
        privateKeyString = keys.Key(dsaKey).toString("openssh")
        with open(publicKeyFile, "w+b") as f:
            f.write(publicKeyString)
        with open(privateKeyFile, "w+b") as f:
            f.write(privateKeyString)
    else:
        with open(publicKeyFile, "rb") as f:
            publicKeyString = f.read()
        with open(privateKeyFile, "rb") as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString


def getECDSAKeys() -> tuple[bytes, bytes]:
    publicKeyFile: str = CowrieConfig.get(
        "ssh", "ecdsa_public_key", fallback="ssh_host_ecdsa_key.pub"
    )
    privateKeyFile: str = CowrieConfig.get(
        "ssh", "ecdsa_private_key", fallback="ssh_host_ecdsa_key"
    )
    if not (os.path.exists(publicKeyFile) and os.path.exists(privateKeyFile)):
        log.msg("Generating new ECDSA keypair...")

        ecdsaKey = ec.generate_private_key(ec.SECP256R1())
        publicKeyString = keys.Key(ecdsaKey).public().toString("openssh")
        privateKeyString = keys.Key(ecdsaKey).toString("openssh")
        with open(publicKeyFile, "w+b") as f:
            f.write(publicKeyString)
        with open(privateKeyFile, "w+b") as f:
            f.write(privateKeyString)
    else:
        with open(publicKeyFile, "rb") as f:
            publicKeyString = f.read()
        with open(privateKeyFile, "rb") as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString


def geted25519Keys() -> tuple[bytes, bytes]:
    publicKeyFile: str = CowrieConfig.get(
        "ssh", "ed25519_public_key", fallback="ssh_host_ed25519_key.pub"
    )
    privateKeyFile: str = CowrieConfig.get(
        "ssh", "ed25519_private_key", fallback="ssh_host_ed25519_key"
    )
    if not (os.path.exists(publicKeyFile) and os.path.exists(privateKeyFile)):
        log.msg("Generating new ed25519 keypair...")

        ed25519Key = Ed25519PrivateKey.generate()
        publicKeyString = keys.Key(ed25519Key).public().toString("openssh")
        privateKeyString = keys.Key(ed25519Key).toString("openssh")
        with open(publicKeyFile, "w+b") as f:
            f.write(publicKeyString)
        with open(privateKeyFile, "w+b") as f:
            f.write(privateKeyString)
    else:
        with open(publicKeyFile, "rb") as f:
            publicKeyString = f.read()
        with open(privateKeyFile, "rb") as f:
            privateKeyString = f.read()
    return publicKeyString, privateKeyString
