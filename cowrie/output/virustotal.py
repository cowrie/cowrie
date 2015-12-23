"""
Send SSH logins to SANS DShield.
See https://isc.sans.edu/ssh.html

"""

import dateutil.parser
import time
import base64
import hmac
import hashlib
import requests
import re
import urllib
import urllib2
import simplejson
import postfile
import virustotal_backlogs

from twisted.python import log
from twisted.internet import threads, reactor

import cowrie.core.output


class Output(cowrie.core.output.Output):

    def __init__(self, cfg):
        self.auth_key = cfg.get('output_virustotal', 'auth_key')
        self.userid = cfg.get('output_virustotal', 'userid')
        self.batch_size = int(cfg.get('output_virustotal', 'batch_size'))
        cowrie.core.output.Output.__init__(self, cfg)

    def start(self):
        self.batch = [] # this is used to store login attempts in batches

    def stop(self):
        pass

    def write(self, entry):
        if entry["eventid"] == 'KIPP0002' or entry["eventid"] == 'KIPP0003':
            date = dateutil.parser.parse(entry["timestamp"])
            self.batch.append({
                'date' : date.date().__str__(),
                'time' : date.time().strftime("%H:%M:%S"),
                'timezone' : time.strftime("%z"),
                'source_ip' : entry['src_ip'],
                'user' : entry['username'],
                'password' : entry['password'],
            })

            if len(self.batch) >= self.batch_size:
                batch_to_send = self.batch
                self.submit_entries(batch_to_send)
                self.batch = []

def get_report(resource, filename, dl_url='unknown', honeypot=None, origin=None):

    apikey = config().get('virustotal', 'apikey')
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": resource,
                  "apikey":   apikey }

    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    j = simplejson.loads(json)

    if j['response_code'] == 1: # file known
        cfg = config()
        args = {'shasum': resource, 'url': dl_url, 'permalink': j['permalink']}

        # we don't use dispatcher, so this check is needed
        if cfg.has_section('database_mysql'):
            mysql_logger = kippo.dblog.mysql.DBLogger(cfg)

            mysql_logger.handleVirustotal(args)

            args_scan = {'shasum': resource, 'json': json}
            mysql_logger.handleVirustotalScan(args_scan)

        if origin == 'db':
            # we don't use dispatcher, so this check is needed
            if cfg.has_section('database_textlog'):
                text_logger = kippo.dblog.textlog.DBLogger(cfg)
                text_logger.handleVirustotalLog('log_from database', args)
        else:
            msg = 'Virustotal report of %s [%s] at %s' % \
                (resource, dl_url, j['permalink'])
            # we need to print msg, because logs from SFTP are dispatched this way
            print msg
            if honeypot:
                honeypot.logDispatch(msg)

    elif j['response_code'] == 0: # file not known
        if origin == 'db':
            return j['response_code']

        msg = 'Virustotal not known, response code: %s' % (j['response_code'])
        print msg
        host = "www.virustotal.com"
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        fields = [("apikey", apikey)]
        filepath = "dl/%s" % resource
        file_to_send = open(filepath, "rb").read()
        files = [("file", filename, file_to_send)]
        json = postfile.post_multipart(host, url, fields, files)
        print json

        msg = 'insert to Virustotal backlog %s [%s]' % \
            (resource, dl_url)
        print msg
        virustotal_backlogs.insert(resource, dl_url)
    else:
        msg = 'Virustotal not known, response code: %s' % (j['response_code'])
        print msg
    return j['response_code']

def make_comment(resource):
    apikey = config().get('virustotal', 'apikey')
    url = "https://www.virustotal.com/vtapi/v2/comments/put"
    parameters = {"resource": resource,
                   "comment": "captured by ssh honeypot",
                   "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    print json
