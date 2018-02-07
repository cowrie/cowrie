import datetime
import re
import time

from twisted.python import log
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError

import cowrie.core.output

from cowrie.core.config import CONFIG



class Output(cowrie.core.output.Output):

    def __init__(self):
        cowrie.core.output.Output.__init__(self)

    def start(self):
        """
        """
        try:
            host = CONFIG.get('output_influx', 'host')
        except:
            host = ''

        try:
            port = CONFIG.getint('output_influx', 'port')
        except:
            port = 8086

        self.client = None
        try:
            self.client = InfluxDBClient(host=host, port=port)
        except InfluxDBClientError as e:
            log.err("output_influx: I/O error({0}): '{1}'".format(
                e.errno, e.strerror))
            return

        if self.client is None:
            log.err("output_influx: cannot instantiate client!")
            return

        if (CONFIG.has_option('output_influx', 'username') and
                CONFIG.has_option('output_influx', 'password')):
            username = CONFIG.get('output_influx', 'username')
            password = CONFIG.get('output_influx', 'password')
            self.client.switch_user(username, password)

        try:
            dbname = CONIFG.get('output_influx', 'database_name')
        else:
            dbname = 'cowrie'

        retention_policy_duration_default = '12w'
        retention_policy_name = dbname + "_retention_policy"

        if CONFIG.has_option('output_influx', 'retention_policy_duration'):
            retention_policy_duration = CONFIG.get(
                'output_influx', 'retention_policy_duration')

            match = re.search('^\d+[dhmw]{1}$', retention_policy_duration)
            if not match:
                log.err(("output_influx: invalid retention policy."
                        "Using default '{}'..").format(
                        retention_policy_duration))
                retention_policy_duration = retention_policy_duration_default
        else:
            retention_policy_duration = retention_policy_duration_default

        database_list = self.client.get_list_database()
        dblist = [str(elem['name']) for elem in database_list]

        if dbname not in dblist:
            self.client.create_database(dbname)
            self.client.create_retention_policy(
                retention_policy_name, retention_policy_duration, 1,
                database=dbname, default=True)
        else:
            retention_policies_list = self.client.get_list_retention_policies(
                database=dbname)
            rplist = [str(elem['name']) for elem in retention_policies_list]
            if retention_policy_name not in rplist:
                self.client.create_retention_policy(
                    retention_policy_name, retention_policy_duration, 1,
                    database=dbname, default=True)
            else:
                self.client.alter_retention_policy(
                    retention_policy_name, database=dbname,
                    duration=retention_policy_duration,
                    replication=1, default=True)

        self.client.switch_database(dbname)

    def stop(self):
        pass

    def write(self, entry):
        if self.client is None:
            log.err("output_influx: client object is not instantiated")
            return

        # event id
        eventid = entry['eventid']

        # measurement init
        m = {
            'measurement': eventid.replace('.','_'),
            'tags': {
                'session': entry['session'],
                'src_ip': entry['src_ip']
            },
            'fields': {
                'sensor': self.sensor
            },
        }

        # event parsing
        if eventid in ['cowrie.command.failed',
                       'cowrie.command.input']:
            m['fields'].update({
                'input': entry['input'],
            })

        elif eventid == 'cowrie.session.connect':
            m['fields'].update({
                'protocol': entry['protocol'],
                'src_port': entry['src_port'],
                'dst_port': entry['dst_port'],
                'dst_ip': entry['dst_ip'],
            })

        elif eventid in ['cowrie.login.success', 'cowrie.login.failed']:
            m['fields'].update({
                'username': entry['username'],
                'password': entry['password'],
            })

        elif eventid == 'cowrie.session.file_download':
            m['fields'].update({
                'shasum': entry.get('shasum'),
                'url': entry.get('url'),
                'outfile': entry.get('outfile')
                })

        elif eventid == 'cowrie.session.file_download.failed':
            m['fields'].update({
                'url': entry.get('url')
                })

        elif eventid == 'cowrie.session.file_upload':
            m['fields'].update({
                'shasum': entry.get('shasum'),
                'outfile': entry.get('outfile'),
            })

        elif eventid == 'cowrie.session.closed':
            m['fields'].update({
                'duration': entry['duration']
            })

        elif eventid == 'cowrie.client.version':
            m['fields'].update({
                'maccs': ','.join(entry['macCS']),
                'kexalgs': ','.join(entry['kexAlgs']),
                'keyalgs': ','.join(entry['keyAlgs']),
                'version': ','.join(entry['version']),
                'compcs': ','.join(entry['compCS']),
                'enccs': ','.join(entry['encCS'])
            })

        elif eventid == 'cowrie.client.size':
            m['fields'].update({
                'height': entry['height'],
                'width': entry['width'],
            })

        elif eventid == 'cowrie.client.var':
            m['fields'].update({
                'name': entry['name'],
                'value': entry['value'],
            })

        elif eventid == 'cowrie.client.fingerprint':
            m['fields'].update({
                'fingerprint': entry['fingerprint']
            })

            # cowrie.direct-tcpip.data, cowrie.direct-tcpip.request
            # cowrie.log.closed cowrie.log.open
            # are not implemented
        else:
            # other events should be handled
            log.err(
                "output_influx: event '{}' not handled. Skipping..".format(
                    eventid))
            return

        result = self.client.write_points([m])

        if not result:
            log.err("output_influx: error when writing '{}' measurement"
                    "in the db.".format(eventid))
