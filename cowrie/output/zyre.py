import cowrie.core.output
from csirtg_indicator import Indicator

from pprint import pprint
import logging
import os
from pyzyre.utils import resolve_endpoint
from pyzyre.chat import task
import names
from czmq import Zactor, zactor_fn, create_string_buffer
import zmq
from time import sleep

#logger = logging.getLogger(__name__)
from twisted.logger import Logger
logger = Logger()

GROUP = os.environ.get('COWRIE_ZYRE_GROUP', 'ZYRE')
INTERFACE = os.environ.get('ZSYS_INTERFACE', 'eth0')
SERVICE_PORT = os.environ.get('ZYRE_PORT', '49155')


class Output(cowrie.core.output.Output):
    def __init__(self, cfg):
        cowrie.core.output.Output.__init__(self, cfg)

        self.group = cfg.get('output_zyre', 'group') or GROUP
        self.interface = cfg.get('output_zyre', 'interface') or INTERFACE
        self.service_port = SERVICE_PORT

        self.port = 22
        self.protocol = 'tcp'
        self.tags = ['scanner', 'ssh']
        self.actor = None
        self._actor = None
        self.endpoint = None
        self.task = zactor_fn(task)

        actor_args = [
            'channel=%s' % self.group,
            'beacon=1',
        ]

        actor_args = ','.join(actor_args)
        self.actor_args = create_string_buffer(actor_args)

        logger.info('staring zyre...')

        # disable CZMQ from capturing SIGINT
        os.environ['ZSYS_SIGHANDLER'] = 'false'

        # signal zbeacon in czmq
        if not os.environ.get('ZSYS_INTERFACE'):
            os.environ["ZSYS_INTERFACE"] = self.interface

        self._actor = Zactor(self.task, self.actor_args)
        self.actor = zmq.Socket(shadow=self._actor.resolve(self._actor).value)
        sleep(0.1)
        logger.info('zyre started')

    def start(self):
        pass

    def stop(self):
        logger.info('stopping zyre')
        self.actor.send_multipart(['$$STOP', ''.encode('utf-8')])
        sleep(0.01)  # cleanup
        logger.info('stopping zyre')

    def write(self, e):
        sid = e['session']

        i = {
            'indicator': e['src_ip'],
            'portlist': self.port,
            'protocol': self.protocol,
            'tags': self.tags,
            'firsttime': e['timestamp'],
            'lasttime': e['timestamp']
        }

        i = Indicator(**i)

        self.actor.send_multipart(['SHOUT', str(i).encode('utf-8')])

        logger.info('sent indicator %s ' % i.indicator)
