# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2016 Dave Germiquet
# See LICENSE for details.

from __future__ import division, absolute_import

import pickle
import copy

from cowrie.shell import fs


class FakeServer:
    """
    @ivar cfg Configuration for honeypot
    @ivar hostname Servers Host Name
    @ivar fs File System for cowrie to use
    """
    def __init__(self, cfg):
        self.cfg = cfg
        self.arch = 'linux-x64-lsb'
        self.hostname = "unitTest"

        self.pckl = pickle.load(
            open(cfg.get('honeypot', 'filesystem_file'), 'rb'))
        self.fs = fs.HoneyPotFilesystem(copy.deepcopy(self.pckl), self.cfg)


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
        self.cfg = server.cfg

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

