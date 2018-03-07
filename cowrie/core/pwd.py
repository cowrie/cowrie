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

"""
This module contains ...
"""

from twisted.python import log


class Passwd(object):
    """
    This class contains code to handle the users and their properties in
    /etc/passwd. Note that contrary to the name, it does not handle any
    passwords.
    """

    def __init__(self, cfg):
        self.passwd_file = '%s/etc/passwd' % (cfg.get('honeypot',
            'contents_path'),)
        self.load()


    def load(self):
        """
        Load /etc/passwd
        """
        self.passwd = []
        with open(self.passwd_file, 'r') as f:
            while True:
                rawline = f.readline()
                if not rawline:
                    break

                line = rawline.strip()
                if not line:
                    continue

                if line.startswith('#'):
                    continue

                (pw_name, pw_passwd, pw_uid, pw_gid, pw_gecos, pw_dir,
                    pw_shell) = line.split(':')

                e = {}
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


    def getpwnam(self, name):
        """
        Get passwd entry for username
        """
        for _ in self.passwd:
            if name == _["pw_name"]:
                return _
        raise KeyError("getpwnam(): name not found in passwd file: " + name)


    def getpwuid(self, uid):
        """
        Get passwd entry for uid
        """
        for _ in self.passwd:
            if uid == _["pw_uid"]:
                return _
        raise KeyError("getpwuid(): uid not found in passwd file: " + uid)



class Group(object):
    """
    This class contains code to handle the groups and their properties in
    /etc/group.
    """

    def __init__(self, cfg):
        self.group_file = '%s/etc/group' % (cfg.get('honeypot',
            'contents_path'),)
        self.load()


    def load(self):
        """
        Load /etc/group
        """
        self.group = []
        with open(self.group_file, 'r') as f:
            while True:
                rawline = f.readline()
                if not rawline:
                    break

                line = rawline.strip()
                if not line:
                    continue

                if line.startswith('#'):
                    continue

                (gr_name, gr_passwd, gr_gid, gr_mem) = line.split(':')

                e = {}
                e["gr_name"] = gr_name
                try:
                    e["gr_gid"] = int(gr_gid)
                except ValueError:
                    e["gr_gid"] = 1001
                e["gr_mem"] = gr_mem

                self.group.append(e)


    def save(self):
        """
        Save the group db
        Note: this is subject to races between cowrie instances, but hey ...
        """
#        with open(self.group_file, 'w') as f:
#            for (login, uid, passwd) in self.userdb:
#                f.write('%s:%d:%s\n' % (login, uid, passwd))
        raise NotImplementedError


    def getgrnam(self, name):
        """
        Get group entry for groupname
        """
        for _ in self.group:
            if name == _["gr_name"]:
                return _
        raise KeyError("getgrnam(): name not found in group file: " + name)


    def getgrgid(self, uid):
        """
        Get group entry for gid
        """
        for _ in self.group:
            if uid == _["gr_gid"]:
                return _
        raise KeyError("getgruid(): uid not found in group file: " + uid)

