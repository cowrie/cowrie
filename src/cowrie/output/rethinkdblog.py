from __future__ import absolute_import, division

import time
from datetime import datetime

import rethinkdb as r

import cowrie.core.output
from cowrie.core.config import CowrieConfig


def iso8601_to_timestamp(value):
    return time.mktime(datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").timetuple())


RETHINK_DB_SEGMENT = 'output_rethinkdblog'


class Output(cowrie.core.output.Output):
    host = CowrieConfig().get(RETHINK_DB_SEGMENT, 'host')
    port = CowrieConfig().getint(RETHINK_DB_SEGMENT, 'port')
    db = CowrieConfig().get(RETHINK_DB_SEGMENT, 'db')
    table = CowrieConfig().get(RETHINK_DB_SEGMENT, 'table')
    password = CowrieConfig().get(RETHINK_DB_SEGMENT, 'password', raw=True)

    # noinspection PyAttributeOutsideInit
    def start(self):
        self.connection = r.connect(
            host=self.host,
            port=self.port,
            db=self.db,
            password=self.password
        )
        try:
            r.db_create(self.db).run(self.connection)
            r.db(self.db).table_create(self.table).run(self.connection)
        except r.RqlRuntimeError:
            pass

    def stop(self):
        self.connection.close()

    def write(self, logentry):
        for i in list(logentry.keys()):
            # remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]

        if 'timestamp' in logentry:
            logentry['timestamp'] = iso8601_to_timestamp(logentry['timestamp'])

        r.table(self.table).insert(logentry).run(self.connection)
