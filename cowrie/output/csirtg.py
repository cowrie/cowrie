import cowrie.core.output

from csirtgsdk.indicator import Indicator
from csirtgsdk.client import Client
from datetime import datetime
from pprint import pprint
import logging
import os

logger = logging.getLogger(__name__)

USERNAME = os.environ.get('CSIRTG_USER')
FEED = os.environ.get('CSIRTG_FEED')
TOKEN = os.environ.get('CSIRG_TOKEN')


class Output(cowrie.core.output.Output):
    def __init__(self, cfg):
        cowrie.core.output.Output.__init__(self, cfg)
        self.user = cfg.get('output_csirtg', 'username') or USERNAME
        self.feed = cfg.get('output_csirtg', 'feed') or FEED
        self.token = cfg.get('output_csirtg', 'token') or TOKEN
        self.port = os.environ.get('COWRIE_PORT', 22)
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

        today = str(datetime.now().date())
        logger.info('today is %s' % today)

        if not self.context.get(today):
            logger.info('resetting context for %s' % today)
            self.context = {}
            self.context[today] = {}

        if not self.context[today].get(peerIP):
            self.context[today][peerIP] = []

            i = {
                'user': self.user,
                'feed': self.feed,
                'indicator': peerIP,
                'portlist': self.port,
                'protocol': 'tcp',
                'tags': 'scanner,ssh',
                'firsttime': ts,
                'lasttime': ts
            }

            ret = Indicator(self.client, i).submit()

            logger.info('logged to csirtg %s ' % ret['indicator']['location'])
        else:
            pprint(self.context)
        self.context[today][peerIP].append(sid)
