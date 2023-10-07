# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains authentication code
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from os import path
from random import randint
from typing import Any
from re import Pattern

from twisted.python import log

from cowrie.core.config import CowrieConfig

_USERDB_DEFAULTS: list[str] = [
    "root:x:!root",
    "root:x:!123456",
    "root:x:!/honeypot/i",
    "root:x:*",
    "phil:x:*",
    "phil:x:fout",
]


class UserDB:
    """
    By Walter de Jong <walter@sara.nl>
    """

    def __init__(self) -> None:
        self.userdb: dict[
            tuple[Pattern[bytes] | bytes, Pattern[bytes] | bytes], bool
        ] = OrderedDict()
        self.load()

    def load(self) -> None:
        """
        load the user db
        """

        dblines: list[str]
        try:
            with open(
                "{}/userdb.txt".format(CowrieConfig.get("honeypot", "etc_path")),
                encoding="ascii",
            ) as db:
                dblines = db.readlines()
        except OSError:
            log.msg("Could not read etc/userdb.txt, default database activated")
            dblines = _USERDB_DEFAULTS

        for user in dblines:
            if not user.startswith("#"):
                try:
                    login = user.split(":")[0].encode("utf8")
                    password = user.split(":")[2].strip().encode("utf8")
                except IndexError:
                    continue
                else:
                    self.adduser(login, password)

    def checklogin(
        self, thelogin: bytes, thepasswd: bytes, src_ip: str = "0.0.0.0"
    ) -> bool:
        for credentials, policy in self.userdb.items():
            login: bytes | Pattern[bytes]
            passwd: bytes | Pattern[bytes]
            login, passwd = credentials

            if self.match_rule(login, thelogin):
                if self.match_rule(passwd, thepasswd):
                    return policy

        return False

    def match_rule(self, rule: bytes | Pattern[bytes], data: bytes) -> bool | bytes:
        if isinstance(rule, bytes):
            return rule in [b"*", data]
        return bool(rule.search(data))

    def re_or_bytes(self, rule: bytes) -> Pattern[bytes] | bytes:
        """
        Convert a /.../ type rule to a regex, otherwise return the string as-is

        @param login: rule
        @type login: bytes
        """
        res = re.match(rb"/(.+)/(i)?$", rule)
        if res:
            return re.compile(res.group(1), re.IGNORECASE if res.group(2) else 0)

        return rule

    def adduser(self, login: bytes, passwd: bytes) -> None:
        """
        All arguments are bytes

        @param login: user id
        @type login: bytes
        @param passwd: password
        @type passwd: bytes
        """
        user = self.re_or_bytes(login)

        if passwd[0] == ord("!"):
            policy = False
            passwd = passwd[1:]
        else:
            policy = True

        p = self.re_or_bytes(passwd)
        self.userdb[(user, p)] = policy


class AuthRandom:
    """
    Alternative class that defines the checklogin() method.
    Users will be authenticated after a random number of attempts.
    """

    def __init__(self) -> None:
        # Default values
        self.mintry: int = 2
        self.maxtry: int = 5
        self.maxcache: int = 10

        # Are there auth_class parameters?
        if CowrieConfig.has_option("honeypot", "auth_class_parameters"):
            parameters: str = CowrieConfig.get("honeypot", "auth_class_parameters")
            parlist: list[str] = parameters.split(",")
            if len(parlist) == 3:
                self.mintry = int(parlist[0])
                self.maxtry = int(parlist[1])
                self.maxcache = int(parlist[2])

        if self.maxtry < self.mintry:
            self.maxtry = self.mintry + 1
            log.msg(f"maxtry < mintry, adjusting maxtry to: {self.maxtry}")

        self.uservar: dict[Any, Any] = {}
        self.uservar_file: str = "{}/auth_random.json".format(
            CowrieConfig.get("honeypot", "state_path")
        )
        self.loadvars()

    def loadvars(self) -> None:
        """
        Load user vars from json file
        """
        if path.isfile(self.uservar_file):
            with open(self.uservar_file, encoding="utf-8") as fp:
                try:
                    self.uservar = json.load(fp)
                except Exception:
                    self.uservar = {}

    def savevars(self) -> None:
        """
        Save the user vars to json file
        """
        data = self.uservar
        # Note: this is subject to races between cowrie logins
        with open(self.uservar_file, "w", encoding="utf-8") as fp:
            json.dump(data, fp)

    def checklogin(self, thelogin: bytes, thepasswd: bytes, src_ip: str) -> bool:
        """
        Every new source IP will have to try a random number of times between
        'mintry' and 'maxtry' before succeeding to login.
        All username/password combinations  must be different.
        The successful login combination is stored with the IP address.
        Successful username/passwords pairs are also cached for 'maxcache' times.
        This is to allow access for returns from different IP addresses.
        Variables are saved in 'uservar.json' in the data directory.
        """

        auth: bool = False
        userpass: str = str(thelogin) + ":" + str(thepasswd)

        if "cache" not in self.uservar:
            self.uservar["cache"] = []
        cache = self.uservar["cache"]

        # Check if it is the first visit from src_ip
        if src_ip not in self.uservar:
            self.uservar[src_ip] = {}
            ipinfo = self.uservar[src_ip]
            ipinfo["try"] = 0
            if userpass in cache:
                log.msg(f"first time for {src_ip}, found cached: {userpass}")
                ipinfo["max"] = 1
                ipinfo["user"] = str(thelogin)
                ipinfo["pw"] = str(thepasswd)
                auth = True
                self.savevars()
                return auth
            ipinfo["max"] = randint(self.mintry, self.maxtry)
            log.msg("first time for {}, need: {}".format(src_ip, ipinfo["max"]))
        else:
            if userpass in cache:
                ipinfo = self.uservar[src_ip]
                log.msg(f"Found cached: {userpass}")
                ipinfo["max"] = 1
                ipinfo["user"] = str(thelogin)
                ipinfo["pw"] = str(thepasswd)
                auth = True
                self.savevars()
                return auth

        ipinfo = self.uservar[src_ip]

        # Fill in missing variables
        if "max" not in ipinfo:
            ipinfo["max"] = randint(self.mintry, self.maxtry)
        if "try" not in ipinfo:
            ipinfo["try"] = 0
        if "tried" not in ipinfo:
            ipinfo["tried"] = []

        # Don't count repeated username/password combinations
        if userpass in ipinfo["tried"]:
            log.msg("already tried this combination")
            self.savevars()
            return auth

        ipinfo["try"] += 1
        attempts: int = ipinfo["try"]
        need: int = ipinfo["max"]
        log.msg(f"login attempt: {attempts}")

        # Check if enough login attempts are tried
        if attempts < need:
            self.uservar[src_ip]["tried"].append(userpass)
        elif attempts == need:
            ipinfo["user"] = str(thelogin)
            ipinfo["pw"] = str(thepasswd)
            cache.append(userpass)
            if len(cache) > self.maxcache:
                cache.pop(0)
            auth = True
        # Returning after successful login
        elif attempts > need:
            if "user" not in ipinfo or "pw" not in ipinfo:
                log.msg("return, but username or password not set!!!")
                ipinfo["tried"].append(userpass)
                ipinfo["try"] = 1
            else:
                log.msg(
                    "login return, expect: [{}/{}]".format(ipinfo["user"], ipinfo["pw"])
                )
                if thelogin == ipinfo["user"] and str(thepasswd) == ipinfo["pw"]:
                    auth = True
        self.savevars()
        return auth
