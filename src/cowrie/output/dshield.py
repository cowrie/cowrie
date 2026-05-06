"""
Send SSH logins to SANS DShield.
See https://isc.sans.edu/ssh.html
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import time
import os
import json
import dateutil.parser

# TODO: use `treq`
import requests
from twisted.internet import reactor, threads
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

HTTP_TIMEOUT = 10
VERSION = 20260506

class Output(cowrie.core.output.Output):
    """
    dshield output
    """

    debug: bool = False
    userid: str
    batch_size: int
    batch: list
    lastcommand: str
    hassh: str

    def start(self):
        self.auth_key = CowrieConfig.get("output_dshield", "auth_key")
        self.userid = CowrieConfig.get("output_dshield", "userid")
        self.batch_size = CowrieConfig.getint("output_dshield", "batch_size")
        self.debug = CowrieConfig.getboolean("output_dshield", "debug", fallback=False)
        self.lastcommand = ''
        self.hassh = ''
        self.banner = ''
        self.batch = []  # This is used to store login attempts in batches

    def stop(self):
        pass

    def write(self, event):
        if (
            event["eventid"] == "cowrie.login.success"
            or event["eventid"] == "cowrie.login.failed"
        ):
            self.batch.append(
                {
                    "timestamp": int(event["time"]),
                    "source_ip": event["src_ip"],
                    "user": event["username"],
                    "password": event["password"],
                    "lastcommand": self.lastcommand,
                    "hassh": self.hassh,
                    "banner": self.banner
                }
            )
            if self.debug:
                log.msg(f"dshield: log appended batch size {len(self.batch)} max size {self.batch_size}")
            if len(self.batch) >= self.batch_size:
                batch_to_send = self.batch
                if self.debug:
                    log.msg(f"dshield: submit entry. batch size reached.")
                self.submit_entries(batch_to_send)
                self.batch = []
        if ( event["eventid"] == "cowrie.command.input" ):
            self.lastcommand = event["input"]
        if ( event["eventid"] == "cowrie.client.kex" ):
            self.hassh = event["hassh"]
        if ( event["eventid"] == "cowrie.client.version" ):
            self.banner = event["version"]


    def transmission_error(self, batch):
        self.batch.extend(batch)
        if len(self.batch) > self.batch_size * 2:
            self.batch = self.batch[-self.batch_size :]

    def submit_entries(self, batch):
        """
        DShield logs are sent to the https://www.dshield.org/submitapi/ endpoint.
        For debugging, use https://www.dshield.org/devsubmitapi/
        """

        url = 'https://www.dshield.org/submitapi/'
        if self.debug:
            url = 'https://www.dshield.org/devsubmitapi/'
            log.msg(f"using debug url {url}")

        # Create authentication header
            
        nonce = base64.b64encode(os.urandom(8)).decode()
        myhash = hmac.new(
            (nonce + str(self.userid)).encode('utf-8'),
            msg=self.auth_key.encode('utf-8'),
            digestmod=hashlib.sha256
        ).digest()
        hash64 = base64.b64encode(myhash).decode()
        auth_header = f'ISC-HMAC-SHA256 Credentials={hash64} Userid={self.userid} Nonce={nonce.rstrip()}'
        if self.debug:
            log.msg(f"dshield authentication header {auth_header}")

        # create message
            
        dshield_msg = {
            'type': 'cowrie',
            'logs': batch,
            'authheader': auth_header
        }
        
        headers = {
            'content-type': 'application/json',
            'User-Agent': f"Cowrie-{VERSION}",
            'X-ISC-Authorization': auth_header,
            'X-ISC-LogType': "cowrie"
        }

        req = threads.deferToThread(
            requests.request,
            method="POST",
            url=url,
            headers=headers,
            timeout=HTTP_TIMEOUT,
            data=json.dumps(dshield_msg)
        )

        def check_response(resp):
            failed = False
            response = resp.content.decode("utf8")

            if self.debug:
                log.msg(f"dshield: status code {resp.status_code}")
                log.msg(f"dshield: response {resp.content}")

            if resp.ok:
                log.msg(f"dshield: submit response {response}")
            else:
                log.msg(f"dshield ERROR: error {resp.status_code}.")
                log.msg(f"dshield response was {response}")
                failed = True
            if failed:
                # Something went wrong, we need to add them to batch.
                reactor.callFromThread(self.transmission_error, batch)
        req.addCallback(check_response)
