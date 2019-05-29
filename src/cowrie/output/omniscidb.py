# A simple logger to export events to omnisci

from __future__ import absolute_import, division

import geoip2.database

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
        self.url = None
        self.outfile = None
        self.shasum = None
        self.download_result = None
        self.was_upload = None
        self.src_lon = None
        self.src_lat = None
        self.src_city = None
        self.src_state = None
        self.src_zip_code = None
        self.src_country = None
        self.src_country_iso = None

    def make_tuple(self):
        return (self.session,
                self.event_time,
                self.sensor_id,
                self.ip_address,
                self.username,
                self.password,
                self.login_result,
                self.command_input,
                self.command_result,
                self.url,
                self.outfile,
                self.shasum,
                self.download_result,
                self.was_upload,
                self.src_lon,
                self.src_lat,
                self.src_city,
                self.src_state,
                self.src_zip_code,
                self.src_country,
                self.src_country_iso
                )

    def set_src_geo(self, src_geo_tuple):
        self.src_lon = src_geo_tuple[0]
        self.src_lat = src_geo_tuple[1]
        self.src_city = src_geo_tuple[2]
        self.src_state = src_geo_tuple[3]
        self.src_zip_code = src_geo_tuple[4]
        self.src_country = src_geo_tuple[5]
        self.src_country_iso = src_geo_tuple[6]


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
        self.mmdb_location = CowrieConfig().get(
            'output_omniscidb', 'mmdb_location', fallback=None)
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

        if self.mmdb_location is not None:
            self.mmdb_geo = geoip2.database.Reader(self.mmdb_location)

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
                command_result TEXT ENCODING DICT(32), \
                url TEXT ENCODING DICT(32),\
                outfile TEXT ENCODING DICT(32),\
                shasum TEXT ENCODING DICT(32),\
                download_result TEXT ENCODING DICT(32),\
                was_upload TEXT ENCODING DICT(32),\
                src_lon float,\
                src_lat float,\
                src_city TEXT ENCODING DICT(32),\
                src_state TEXT ENCODING DICT(32),\
                src_zip_code TEXT ENCODING DICT(32),\
                src_country TEXT ENCODING DICT(16),\
                src_country_iso TEXT ENCODING DICT(16))")

        except Exception as e:
            log.msg("Failed to create table got error {0}".format(e))

    def maxmind_geo_lookup(self, reader, ip):
        try:
            response = reader.city(ip)
            return (float(response.location.longitude),
                    float(response.location.latitude),
                    str(response.city.name),
                    str(response.subdivisions.most_specific.name),
                    str(response.postal.code),
                    str(response.country.name),
                    str(response.country.iso_code))
        except Exception as e:
            log.msg("Failed to lookup ip {0}".format(e))
            return None

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

            # If Maxmind is loaded set the geoip tuple.
            if self.mmdb_geo:
                src_geo_tuple = (
                    self.maxmind_geo_lookup(
                        self.mmdb_geo, cowrie_output.ip_address))
                if src_geo_tuple is not None:
                    cowrie_output.set_src_geo(src_geo_tuple)

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

        # Handle upload and download events

        elif 'cowrie.session.file' in entry["eventid"]:
            cowrie_output.url = entry['url']
            if entry["eventid"] == 'cowrie.session.file_download':
                cowrie_output.shasum = entry['shasum']
                cowrie_output.outfile = entry['outfile']
                cowrie_output.download_result = "1"
                self.load_data([cowrie_output.make_tuple()])
            if entry["eventid"] == 'cowrie.session.file_download.failed':
                cowrie_output.download_result = "0"
                self.load_data([cowrie_output.make_tuple()])
            if entry["eventid"] == 'cowrie.session.file_upload':
                cowrie_output.was_upload = "1"
                cowrie_output.shasum = entry['shasum']
                cowrie_output.outfile = entry['outfile']
                self.load_data([cowrie_output.make_tuple()])
