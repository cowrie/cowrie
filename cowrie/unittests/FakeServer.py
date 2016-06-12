__author__ = 'davegermiquet'
import pickle
from cowrie.core import fs
import copy

class CfgContainer:

    def has_option(self,argument1,argument):
        return True

    def get(self,argument1,argument2):
        if argument2 == "internet_facing_ip":
            return "111.111.111.111"
        if argument2 == "fakeaddr":
            return "192.168.1.1"

class FakeServer:
    def __init__(self, cfg):
        self.cfg = CfgContainer()

        # self.servers = {}
        self.hostname = "unitTest"

        # load the pickle file system here, so servers can copy it later
        self.pckl = pickle.load(file('../../data/fs.pickle', 'rb'))
        self.fs = fs.HoneyPotFilesystem(copy.deepcopy(self.pckl),self.cfg)

class FakeAvatar:

    def __init__(self,server):
        self.avatar = self
        self.server = server
        self.cfg = server.cfg

        self.uid = 1
        self.gid = 1
        self.home = "/root"
        self.username = "root"
        self.environ = {
            'LOGNAME': self.username,
            'USER': self.username,
            'HOME': self.home,
            'TMOUT': '1800'}
        if self.uid==0:
           self.environ['PATH']='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        else:
           self.environ['PATH']='/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games'

