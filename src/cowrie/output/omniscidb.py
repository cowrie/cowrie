# A simple logger to export events to omnisci

from __future__ import absolute_import, division

import pymapd as pmd

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class CowrieOutput():
    def __init__(self):
        self.session = None
        self.event_time = None
        self.sensor_id = None
        self.ip_address = None
        self.username = None
        self.password = None
        self.login_result = None
        self.command_input = None
        self.command_result = None

    def make_tuple(self):
        return (self.session,
                self.event_time,
                self.sensor_id,
                self.ip_address,
                self.username,
                self.password,
                self.login_result,
                self.command_input,
                self.command_result
                )


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
            log.msg("Failed to login to OmniSciDB: got error {0}".format(e))

        try:
            # Create our Tables for Cowrie
            self.cursor.execute("CREATE TABLE cowrie_sessions \
            (session TEXT ENCODING DICT(32),\
                event_time TIMESTAMP(0),\
                sensor TEXT ENCODING DICT(32),\
                ip_address TEXT ENCODING DICT(32), \
                username TEXT ENCODING DICT(32),\
                password TEXT ENCODING DICT(32),\
                login_result TEXT ENCODING DICT(32),\
                command_input TEXT ENCODING DICT(32),\
                command_result TEXT ENCODING DICT(32))")

        except Exception as e:
            log.msg("Failed to create table got error {0}".format(e))

    def load_data(self, data_dict):
        try:
            self.connection.load_table_rowwise("cowrie_sessions", data_dict)
        except Exception as e:
            log.msg("output_omniscidb: Error %s" % (e))

    def stop(self):
        log.msg("Closing OmniSciDB connection")
        self.connection.close()

    def write(self, entry):
        # Create class that holds basic data for all events
        cowrie_output = CowrieOutput()
        cowrie_output.session = entry["session"]
        cowrie_output.event_time = entry["time"]
        cowrie_output.sensor_id = self.sensor

        # Handle the basic connection
        if entry["eventid"] == 'cowrie.session.connect':
            cowrie_output.ip_address = entry["src_ip"]
            self.load_data([cowrie_output.make_tuple()])

        # Handle the login events
        elif 'cowrie.login' in entry["eventid"]:
            cowrie_output.ip_address = entry["src_ip"]
            cowrie_output.username = entry['username']
            cowrie_output.password = entry['password']

            if entry["eventid"] == 'cowrie.login.success':
                cowrie_output.login_result = "1"
                self.load_data([cowrie_output.make_tuple()])
            if entry["eventid"] == 'cowrie.login.failed':
                cowrie_output.login_result = "0"
                self.load_data([cowrie_output.make_tuple()])

        # Handle the command events
        elif 'cowrie.command' in entry["eventid"]:
            cowrie_output.command_input = entry["input"]
            if entry["eventid"] == 'cowrie.command.input':
                cowrie_output.command_result = "1"
                self.load_data([cowrie_output.make_tuple()])
            if entry["eventid"] == 'cowrie.command.failed':
                cowrie_output.command_result = "0"
                self.load_data([cowrie_output.make_tuple()])

        elif entry["eventid"] == 'cowrie.session.file_download':
            pass
        elif entry["eventid"] == 'cowrie.session.file_download.failed':
            pass
        elif entry["eventid"] == 'cowrie.session.file_upload':
            pass
        elif entry["eventid"] == 'cowrie.session.input':
            pass
