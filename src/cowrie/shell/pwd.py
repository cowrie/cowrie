# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.


from __future__ import annotations
from binascii import crc32
from random import randint, seed
from typing import Any, Union

from twisted.python import log

from cowrie.core.config import CowrieConfig


class Passwd:
    """
    This class contains code to handle the users and their properties in
    /etc/passwd. Note that contrary to the name, it does not handle any
    passwords.
    """

    passwd_file = "{}/etc/passwd".format(CowrieConfig.get("honeypot", "contents_path"))
    passwd: list[dict[str, Any]]

    def __init__(self) -> None:
        self.load()

    def load(self) -> None:
        """
        Load /etc/passwd
        """
        self.passwd = []
        with open(self.passwd_file, encoding="ascii") as f:
            while True:
                rawline = f.readline()
                if not rawline:
                    break

                line = rawline.strip()
                if not line:
                    continue

                if line.startswith("#"):
                    continue

                if len(line.split(":")) != 7:
                    log.msg("Error parsing line `" + line + "` in <honeyfs>/etc/passwd")
                    continue

                (
                    pw_name,
                    pw_passwd,
                    pw_uid,
                    pw_gid,
                    pw_gecos,
                    pw_dir,
                    pw_shell,
                ) = line.split(":")

                e: dict[str, Union[str, int]] = {}
                e["pw_name"] = pw_name
                e["pw_passwd"] = pw_passwd
                e["pw_gecos"] = pw_gecos
                e["pw_dir"] = pw_dir
                e["pw_shell"] = pw_shell
                try:
                    e["pw_uid"] = int(pw_uid)
                except ValueError:
                    e["pw_uid"] = 1001
                try:
                    e["pw_gid"] = int(pw_gid)
                except ValueError:
                    e["pw_gid"] = 1001

                self.passwd.append(e)

    def save(self):
        """
        Save the user db
        Note: this is subject to races between cowrie instances, but hey ...
        """
        #        with open(self.passwd_file, 'w') as f:
        #            for (login, uid, passwd) in self.userdb:
        #                f.write('%s:%d:%s\n' % (login, uid, passwd))
        raise NotImplementedError

    def getpwnam(self, name: str) -> dict[str, Any]:
        """
        Get passwd entry for username
        """
        for e in self.passwd:
            if e["pw_name"] == name:
                return e
        raise KeyError("getpwnam(): name not found in passwd file: " + name)

    def getpwuid(self, uid: int) -> dict[str, Any]:
        """
        Get passwd entry for uid
        """
        for e in self.passwd:
            if uid == e["pw_uid"]:
                return e
        raise KeyError("getpwuid(): uid not found in passwd file: " + str(uid))

    def setpwentry(self, name: str) -> dict[str, Any]:
        """
        If the user is not in /etc/passwd, creates a new user entry for the session
        """

        # ensure consistent uid and gid
        seed_id = crc32(name.encode("utf-8"))
        seed(seed_id)

        e: dict[str, Any] = {}
        e["pw_name"] = name
        e["pw_passwd"] = "x"
        e["pw_gecos"] = 0
        e["pw_dir"] = "/home/" + name
        e["pw_shell"] = "/bin/bash"
        e["pw_uid"] = randint(1500, 10000)
        e["pw_gid"] = e["pw_uid"]
        self.passwd.append(e)
        return e


class Group:
    """
    This class contains code to handle the groups and their properties in
    /etc/group.
    """

    group_file = "{}/etc/group".format(CowrieConfig.get("honeypot", "contents_path"))
    group: list[dict[str, Any]]

    def __init__(self):
        self.load()

    def load(self) -> None:
        """
        Load /etc/group
        """
        self.group = []
        with open(self.group_file, encoding="ascii") as f:
            while True:
                rawline = f.readline()
                if not rawline:
                    break

                line = rawline.strip()
                if not line:
                    continue

                if line.startswith("#"):
                    continue

                (gr_name, _, gr_gid, gr_mem) = line.split(":")

                e: dict[str, Union[str, int]] = {}
                e["gr_name"] = gr_name
                try:
                    e["gr_gid"] = int(gr_gid)
                except ValueError:
                    e["gr_gid"] = 1001
                e["gr_mem"] = gr_mem

                self.group.append(e)

    def save(self) -> None:
        """
        Save the group db
        Note: this is subject to races between cowrie instances, but hey ...
        """
        #        with open(self.group_file, 'w') as f:
        #            for (login, uid, passwd) in self.userdb:
        #                f.write('%s:%d:%s\n' % (login, uid, passwd))
        raise NotImplementedError

    def getgrnam(self, name: str) -> dict[str, Any]:
        """
        Get group entry for groupname
        """
        for e in self.group:
            if name == e["gr_name"]:
                return e
        raise KeyError("getgrnam(): name not found in group file: " + name)

    def getgrgid(self, uid: int) -> dict[str, Any]:
        """
        Get group entry for gid
        """
        for e in self.group:
            if uid == e["gr_gid"]:
                return e
        raise KeyError("getgruid(): uid not found in group file: " + str(uid))
