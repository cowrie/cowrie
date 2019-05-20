from __future__ import absolute_import, division

import os
from datetime import datetime

from csirtgsdk.client import Client
from csirtgsdk.indicator import Indicator

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

USERNAME = os.environ.get('CSIRTG_USER')
FEED = os.environ.get('CSIRTG_FEED')
TOKEN = os.environ.get('CSIRG_TOKEN')
DESCRIPTION = os.environ.get('CSIRTG_DESCRIPTION', 'random scanning activity')


class Output(cowrie.core.output.Output):
    """
    csirtg output
    """

    def start(self, ):
        self.user = CowrieConfig().get('output_csirtg', 'username') or USERNAME
        self.feed = CowrieConfig().get('output_csirtg', 'feed') or FEED
        self.token = CowrieConfig().get('output_csirtg', 'token') or TOKEN
        self.description = CowrieConfig().get('output_csirtg', 'description', fallback=DESCRIPTION)
        self.context = {}
        self.client = Client(token=self.token)

    def stop(self):
        pass

    def write(self, e):
        peerIP = e['src_ip']
        ts = e['timestamp']
        system = e.get('system', None)

        if system not in ['cowrie.ssh.factory.CowrieSSHFactory',
                          'cowrie.telnet.transport.HoneyPotTelnetFactory']:
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
