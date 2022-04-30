from __future__ import annotations
import json
from configparser import NoOptionError

import redis

import cowrie.core.output
from cowrie.core.config import CowrieConfig

SEND_METHODS = {
    "lpush": lambda redis_client, key, message: redis_client.lpush(key, message),
    "rpush": lambda redis_client, key, message: redis_client.rpush(key, message),
    "publish": lambda redis_client, key, message: redis_client.publish(key, message),
}


class Output(cowrie.core.output.Output):
    """
    redis output
    """

    def start(self):
        """
        Initialize pymisp module and ObjectWrapper (Abstract event and object creation)
        """
        host: str = CowrieConfig.get("output_redis", "host")
        port: int = CowrieConfig.getint("output_redis", "port")

        try:
            db = CowrieConfig.getint("output_redis", "db")
        except NoOptionError:
            db = 0

        try:
            password = CowrieConfig.get("output_redis", "password")
        except NoOptionError:
            password = None

        self.redis = redis.StrictRedis(host=host, port=port, db=db, password=password)

        self.keyname = CowrieConfig.get("output_redis", "keyname")

        try:
            self.send_method = SEND_METHODS[
                CowrieConfig.get("output_redis", "send_method")
            ]
        except (NoOptionError, KeyError):
            self.send_method = SEND_METHODS["lpush"]

    def stop(self):
        pass

    def write(self, logentry):
        """
        Push to redis
        """
        # Add the entry to redis
        for i in list(logentry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith("log_"):
                del logentry[i]
        self.send_method(self.redis, self.keyname, json.dumps(logentry))
