from __future__ import division, absolute_import

import cowrie.core.output
from cowrie.core.config import CONFIG

import redis
import json

class Output(cowrie.core.output.Output):

    def __init__(self):
        cowrie.core.output.Output.__init__(self)

    def start(self):
        """
        Initialize pymisp module and ObjectWrapper (Abstract event and object creation)
        """
        self.host = CONFIG.get('output_redis', 'host')
        self.port = CONFIG.get('output_redis', 'port')
        self.db = CONFIG.get('output_redis', 'db')
        self.keyname = CONFIG.get('output_redis', 'keyname')
        self.redis = redis.StrictRedis(self.host, self.port, self.db)

    def stop(self):
        pass

    def write(self, logentry):
        """
        Push to redis
        """
        # Add the entry to redis
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]
        self.redis.lpush(self.keyname, json.dumps(logentry))
