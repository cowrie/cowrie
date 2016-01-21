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

from twisted.python import log
from twisted.internet import threads, reactor

import cowrie.core.output


class Output(cowrie.core.output.Output):

    def __init__(self, cfg):
        self.auth_key = cfg.get('output_dshield', 'auth_key')
        self.userid = cfg.get('output_dshield', 'userid')
        self.batch_size = int(cfg.get('output_dshield', 'batch_size'))
        cowrie.core.output.Output.__init__(self, cfg)


    def start(self):
        self.batch = [] # This is used to store login attempts in batches


    def stop(self):
        pass


    def write(self, entry):
        if entry["eventid"] == 'cowrie.login.success' or entry["eventid"] == 'cowrie.login.failed':
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


    def transmission_error(self, batch):
        self.batch.extend(batch)
        if len(self.batch) > self.batch_size * 2:
            self.batch = self.batch[-self.batch_size:]


    def submit_entries(self, batch):
        """
        Large parts of this method are adapted from kippo-pyshield by jkakavas
        Many thanks to their efforts. https://github.com/jkakavas/kippo-pyshield
        """
        # The nonce is predefined as explained in the original script :
        # trying to avoid sending the authentication key in the "clear" but
        # not wanting to deal with a full digest like exchange. Using a
        # fixed nonce to mix up the limited userid.
        _nonceb64 = 'ElWO1arph+Jifqme6eXD8Uj+QTAmijAWxX1msbJzXDM='

        log_output = ''
        for attempt in self.batch:
            log_output += '{0}\t{1}\t{2}\t{3}\t{4}\t{5}\n'.format(attempt['date'],
                attempt['time'], attempt['timezone'], attempt['source_ip'],
                attempt['user'], attempt['password'])

        nonce = base64.b64decode(_nonceb64)
        digest = base64.b64encode(hmac.new('{0}{1}'.format(nonce, self.userid),
            base64.b64decode(self.auth_key), hashlib.sha256).digest())
        auth_header = 'credentials={0} nonce={1} userid={2}'.format(digest, _nonceb64, self.userid)
        headers = {'X-ISC-Authorization': auth_header,
                  'Content-Type':'text/plain',
                  'Content-Length': len(log_output)}
        log.msg(headers)
        req = threads.deferToThread(requests.request,
                                method ='PUT',
                                url = 'https://secure.dshield.org/api/file/sshlog',
                                headers = headers,
                                timeout = 10,
                                data = log_output)


        def check_response(resp):
            failed = False
            response = resp.content
            if resp.status_code == requests.codes.ok:
                sha1_regex = re.compile(r'<sha1checksum>([^<]+)<\/sha1checksum>')
                sha1_match = sha1_regex.search(response)
                if sha1_match is None:
                    log.err('dshield ERROR: Could not find sha1checksum in response')
                    failed = True
                sha1_local = hashlib.sha1()
                sha1_local.update(log_output)
                if sha1_match.group(1) != sha1_local.hexdigest():
                    log.err('dshield ERROR: SHA1 Mismatch {0} {1} .'.format(sha1_match.group(1), sha1_local.hexdigest()))
                    failed = True
                md5_regex = re.compile(r'<md5checksum>([^<]+)<\/md5checksum>')
                md5_match = md5_regex.search(response)
                if md5_match is None:
                    log.err('dshield ERROR: Could not find md5checksum in response')
                    failed = True
                md5_local = hashlib.md5()
                md5_local.update(log_output)
                if md5_match.group(1) != md5_local.hexdigest():
                    log.err('dshield ERROR: MD5 Mismatch {0} {1} .'.format(md5_match.group(1), md5_local.hexdigest()))
                    failed = True
                log.msg('dshield SUCCESS: Sent {0} bytes worth of data to secure.dshield.org'.format(len(log_output)))
            else:
                log.err('dshield ERROR: error {0}.'.format(resp.status_code))
                log.err('Response was {0}'.format(response))
                failed = True

            if failed:
                # Something went wrong, we need to add them to batch.
                reactor.callFromThread(self.transmission_error, batch)

        req.addCallback(check_response)

