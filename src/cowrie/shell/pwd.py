# SPDX-FileCopyrightText: 2015-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause


from __future__ import annotations

import sys
from binascii import crc32
from random import randint, seed
from typing import Any

from twisted.python import log

from cowrie.shell.honeyfs import read_honeyfs_bytes


class Passwd:
    """
    This class contains code to handle the users and their properties in
    /etc/passwd. Note that contrary to the name, it does not handle any
    passwords.
    """

    passwd: list[dict[str, Any]]

    def __init__(self) -> None:
        self.passwd = []
        self.load()

    def load(self) -> None:
        """
        Load /etc/passwd
        """
        try:
            raw = read_honeyfs_bytes("etc/passwd").decode("ascii")
        except Exception as err:
            log.err(err, "ERROR: Failed to load /etc/passwd")
            sys.exit(2)

        for rawline in raw.splitlines():
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

            e: dict[str, str | int] = {}
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

    group: list[dict[str, Any]]

    def __init__(self) -> None:
        self.group = []
        self.load()

    def load(self) -> None:
        """
        Load /etc/group
        """
        try:
            raw = read_honeyfs_bytes("etc/group").decode("ascii")
        except Exception as err:
            log.err(err, "ERROR: Failed to load /etc/group")
            sys.exit(2)

        for rawline in raw.splitlines():
            line = rawline.strip()
            if not line:
                continue

            if line.startswith("#"):
                continue

            (gr_name, _, gr_gid, gr_mem) = line.split(":")

            e: dict[str, str | int] = {}
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
