# A simple logger to export events to omnisci

from __future__ import absolute_import, division

import pymapd as pmd

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    OmniSciDB Output
    """

    def start(self):
        self.host = CowrieConfig().get(
            'output_omniscidb', 'host', fallback=None)
        self.port = CowrieConfig().get(
            'output_omniscidb', 'port', fallback=None)
        self.db = CowrieConfig().get(
            'output_omniscidb', 'db', fallback=None)
        self.protocol = CowrieConfig().get(
            'output_omniscidb', 'protocol', fallback=None)
        self.username = CowrieConfig().get(
            'output_omniscidb', 'username', fallback=None)
        self.password = CowrieConfig().get(
            'output_omniscidb', 'password', fallback=None)
        try:
            self.connection = pmd.connect(user=self.username,
                                          password=self.password,
                                          host=self.host,
                                          dbname=self.db,
                                          protocol=self.protocol,
                                          port=self.port)
            self.cursor = self.connection.cursor()
        except Exception as e:
            log.msg("output_omniscidb: Error %s" % (e))

        # Create our Tables for Cowrie
        # self.cursor.execute("CREATE TABLE cowrie_sessions \
        #    (id TEXT ENCODING DICT(32),\
        #    starttime TIMESTAMP(0),\
        #    sensor TEXT ENCODING DICT(32),\
        #    ip TEXT ENCODING DICT(32))")

    def stop(self):
        log.msg("Closing OmniSciDB connection")
        self.connection.close()

    def write(self, entry):
        sensorid = "test123123"
        if entry["eventid"] == 'cowrie.session.connect':
            data_tup = [(entry["session"], entry["time"], sensorid, entry["src_ip"])]
            self.connection.load_table_rowwise("cowrie_sessions", data_tup)
