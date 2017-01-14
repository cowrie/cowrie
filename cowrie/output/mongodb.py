# -*- coding: utf-8 -*-

import pymongo

from twisted.python import log

import cowrie.core.output


class Output(cowrie.core.output.Output):
    """
    """

    def __init__(self, cfg):
        self.cfg = cfg
        cowrie.core.output.Output.__init__(self, cfg)


    def start(self):
        """
        """
        db_addr = self.cfg.get('output_mongodb', 'connection_string')
        db_name = self.cfg.get('output_mongodb', 'database')

        try:
            self.mongo_client = pymongo.MongoClient(db_addr)
            self.mongo_db = self.mongo_client[db_name]
            self.coll = self.mongo_db['events']
        except Exception, e:
            log.msg('output_mongodb: Error: %s' % str(e))


    def stop(self):
        """
        """
        self.mongo_client.close()


    def write(self, entry):
        """
        """
        for i in list(entry.keys()):
            # Remove twisted 15 legacy keys
            if i.startswith('log_'):
                del entry[i]
        try:
            self.coll.insert_one(entry)
        except Exception,e:
            log.msg('output_mongodb: MongoDB Error: %s' % str(e))
