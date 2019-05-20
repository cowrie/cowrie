# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2016 Dave Germiquet
# See LICENSE for details.

from __future__ import absolute_import, division

from cowrie.shell import fs


class FakeServer:
    """
    @ivar hostname Servers Host Name
    @ivar fs File System for cowrie to use
    """

    def __init__(self):
        self.arch = 'linux-x64-lsb'
        self.hostname = "unitTest"

        self.fs = fs.HoneyPotFilesystem(None, 'arch')
        self.process = None


class FakeAvatar:
    """
    @var avatar itself
    @ivar server server configuration
    @var fs File System for cowrie to use
    @var environ for user
    @var uid for user
    @var
    """

    def __init__(self, server):
        self.avatar = self
        self.server = server

        self.uid = 0
        self.gid = 0
        self.home = "/root"
        self.username = "root"
        self.environ = {
            'LOGNAME': self.username,
            'USER': self.username,
            'HOME': self.home,
            'TMOUT': '1800'}
        if self.uid == 0:
            self.environ[
                'PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        else:
            self.environ[
                'PATH'] = '/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games'
        self.windowSize = [25, 80]
