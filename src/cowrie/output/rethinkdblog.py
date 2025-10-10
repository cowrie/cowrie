from __future__ import annotations
import time
from datetime import datetime

import rethinkdb as r

import cowrie.core.output
from cowrie.core.config import CowrieConfig


def iso8601_to_timestamp(value):
    return time.mktime(datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").timetuple())


RETHINK_DB_SEGMENT = "output_rethinkdblog"


class Output(cowrie.core.output.Output):
    # noinspection PyAttributeOutsideInit
    def start(self):
        self.host = CowrieConfig.get(RETHINK_DB_SEGMENT, "host")
        self.port = CowrieConfig.getint(RETHINK_DB_SEGMENT, "port")
        self.db = CowrieConfig.get(RETHINK_DB_SEGMENT, "db")
        self.table = CowrieConfig.get(RETHINK_DB_SEGMENT, "table")
        self.password = CowrieConfig.get(RETHINK_DB_SEGMENT, "password", raw=True)
        self.connection = r.connect(
            host=self.host, port=self.port, db=self.db, password=self.password
        )
        try:
            r.db_create(self.db).run(self.connection)
            r.db(self.db).table_create(self.table).run(self.connection)
        except r.RqlRuntimeError:
            pass

    def stop(self):
        self.connection.close()

    def write(self, event):
        for i in list(event.keys()):
            # remove twisted 15 legacy keys
            if i.startswith("log_"):
                del event[i]

        if "timestamp" in event:
            event["timestamp"] = iso8601_to_timestamp(event["timestamp"])

        r.table(self.table).insert(event).run(self.connection)
