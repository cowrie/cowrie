from __future__ import division, absolute_import

import cowrie.core.output

from csirtgsdk.indicator import Indicator
from csirtgsdk.client import Client
from datetime import datetime
import logging
import os
from twisted.python import log

USERNAME = os.environ.get('CSIRTG_USER')
FEED = os.environ.get('CSIRTG_FEED')
TOKEN = os.environ.get('CSIRG_TOKEN')
DESCRIPTION = os.environ.get('CSIRTG_DESCRIPTION', 'random scanning activity')


class Output(cowrie.core.output.Output):
    def __init__(self, cfg):
        cowrie.core.output.Output.__init__(self, cfg)
        self.user = cfg.get('output_csirtg', 'username') or USERNAME
        self.feed = cfg.get('output_csirtg', 'feed') or FEED
        self.token = cfg.get('output_csirtg', 'token') or TOKEN
        try:
            self.description = cfg.get('output_csirtg', 'description')
        except Exception:
            self.description = DESCRIPTION
        self.context = {}
        self.client = Client(token=self.token)

    def start(self,):
        pass

    def stop(self):
        pass

    def write(self, e):
        sid = e['session']
        peerIP = e['src_ip']
        ts = e['timestamp']
        system = e['system']

        if system not in ['cowrie.ssh.factory.CowrieSSHFactory', 'cowrie.telnet.transport.HoneyPotTelnetFactory']:
            return

        today = str(datetime.now().date())

        if not self.context.get(today):
            self.context = {}
            self.context[today] = set()

        key = ','.join([peerIP, system])

        if key in self.context[today]:
            return

        self.context[today].add(key)

        tags = 'scanner,ssh'
        port = 22
        if e['system'] == 'cowrie.telnet.transport.HoneyPotTelnetFactory':
            tags = 'scanner,telnet'
            port = 23

        i = {
            'user': self.user,
            'feed': self.feed,
            'indicator': peerIP,
            'portlist': port,
            'protocol': 'tcp',
            'tags': tags,
            'firsttime': ts,
            'lasttime': ts,
            'description': self.description
        }

        ret = Indicator(self.client, i).submit()
        log.msg('logged to csirtg %s ' % ret['location'])

