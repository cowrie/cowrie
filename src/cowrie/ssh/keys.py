# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

from __future__ import annotations

import os
from configparser import NoOptionError, NoSectionError

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from twisted.conch.ssh import keys

from cowrie.core.config import CowrieConfig

RSA_KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537

DSA_KEY_SIZE = 1024


def getRSAKeys() -> tuple[bytes, bytes]:
    """
    If no keys in configfile file, generate but don't write them.
    If keys are defined, but don't exist, create them.
    If keys defined and exists, return contents
    """
    try:
        publicKeyFile: str = CowrieConfig.get("ssh", "rsa_public_key")
        privateKeyFile: str = CowrieConfig.get("ssh", "rsa_private_key")
    except (NoOptionError, NoSectionError):
        rsaKey = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_SIZE,
            backend=default_backend(),
        )
        publicKeyString = keys.Key(rsaKey).public().toString("openssh")
        privateKeyString = keys.Key(rsaKey).toString("openssh")
        return publicKeyString, privateKeyString

    if os.path.exists(publicKeyFile) and os.path.exists(privateKeyFile):
        with open(publicKeyFile, "rb") as f:
            publicKeyString = f.read()
        with open(privateKeyFile, "rb") as f:
            privateKeyString = f.read()
        return publicKeyString, privateKeyString

    rsaKey = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
        backend=default_backend(),
    )
    publicKeyString = keys.Key(rsaKey).public().toString("openssh")
    privateKeyString = keys.Key(rsaKey).toString("openssh")
    with open(publicKeyFile, "w+b") as f:
        f.write(publicKeyString)
    with open(privateKeyFile, "w+b") as f:
        f.write(privateKeyString)
    return publicKeyString, privateKeyString


def getECDSAKeys() -> tuple[bytes, bytes]:
    """
    If no keys in configfile file, generate but don't write them.
    If keys are defined, but don't exist, create them.
    If keys defined and exists, return contents
    """
    try:
        publicKeyFile: str = CowrieConfig.get("ssh", "ecdsa_public_key")
        privateKeyFile: str = CowrieConfig.get("ssh", "ecdsa_private_key")
    except (NoOptionError, NoSectionError):
        ecdsaKey = ec.generate_private_key(ec.SECP256R1())
        publicKeyString = keys.Key(ecdsaKey).public().toString("openssh")
        privateKeyString = keys.Key(ecdsaKey).toString("openssh")
        return publicKeyString, privateKeyString

    if os.path.exists(publicKeyFile) and os.path.exists(privateKeyFile):
        with open(publicKeyFile, "rb") as f:
            publicKeyString = f.read()
        with open(privateKeyFile, "rb") as f:
            privateKeyString = f.read()
        return publicKeyString, privateKeyString

    ecdsaKey = ec.generate_private_key(ec.SECP256R1())
    publicKeyString = keys.Key(ecdsaKey).public().toString("openssh")
    privateKeyString = keys.Key(ecdsaKey).toString("openssh")
    with open(publicKeyFile, "w+b") as f:
        f.write(publicKeyString)
    with open(privateKeyFile, "w+b") as f:
        f.write(privateKeyString)
    return publicKeyString, privateKeyString


def geted25519Keys() -> tuple[bytes, bytes]:
    """
    If no keys in configfile file, generate but don't write them.
    If keys are defined, but don't exist, create them.
    If keys defined and exists, return contents
    """
    try:
        publicKeyFile: str = CowrieConfig.get("ssh", "ed25519_public_key")
        privateKeyFile: str = CowrieConfig.get("ssh", "ed25519_private_key")
    except (NoOptionError, NoSectionError):
        ed25519Key = Ed25519PrivateKey.generate()
        publicKeyString = keys.Key(ed25519Key).public().toString("openssh")
        privateKeyString = keys.Key(ed25519Key).toString("openssh")
        return publicKeyString, privateKeyString

    if os.path.exists(publicKeyFile) and os.path.exists(privateKeyFile):
        with open(publicKeyFile, "rb") as f:
            publicKeyString = f.read()
        with open(privateKeyFile, "rb") as f:
            privateKeyString = f.read()
        return publicKeyString, privateKeyString

    ed25519Key = Ed25519PrivateKey.generate()
    publicKeyString = keys.Key(ed25519Key).public().toString("openssh")
    privateKeyString = keys.Key(ed25519Key).toString("openssh")
    with open(publicKeyFile, "w+b") as f:
        f.write(publicKeyString)
    with open(privateKeyFile, "w+b") as f:
        f.write(privateKeyString)
    return publicKeyString, privateKeyString
