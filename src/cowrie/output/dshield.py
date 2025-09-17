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

import dateutil.parser

# TODO: use `treq`
import requests

from twisted.internet import reactor
from twisted.internet import threads
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

HTTP_TIMEOUT = 10


class Output(cowrie.core.output.Output):
    """
    dshield output
    """

    debug: bool = False
    userid: str
    batch_size: int
    batch: list

    def start(self):
        self.auth_key = CowrieConfig.get("output_dshield", "auth_key")
        self.userid = CowrieConfig.get("output_dshield", "userid")
        self.batch_size = CowrieConfig.getint("output_dshield", "batch_size")
        self.debug = CowrieConfig.getboolean("output_dshield", "debug", fallback=False)
        self.batch = []  # This is used to store login attempts in batches

    def stop(self):
        pass

    def write(self, event):
        if (
            event["eventid"] == "cowrie.login.success"
            or event["eventid"] == "cowrie.login.failed"
        ):
            date = dateutil.parser.parse(event["timestamp"])
            self.batch.append(
                {
                    "date": str(date.date()),
                    "time": date.time().strftime("%H:%M:%S"),
                    "timezone": time.strftime("%z"),
                    "source_ip": event["src_ip"],
                    "user": event["username"],
                    "password": event["password"],
                }
            )

            if len(self.batch) >= self.batch_size:
                batch_to_send = self.batch
                self.submit_entries(batch_to_send)
                self.batch = []

    def transmission_error(self, batch):
        self.batch.extend(batch)
        if len(self.batch) > self.batch_size * 2:
            self.batch = self.batch[-self.batch_size :]

    def submit_entries(self, batch):
        """
        Large parts of this method are adapted from kippo-pyshield by jkakavas
        Many thanks to their efforts. https://github.com/jkakavas/kippo-pyshield
        """
        # The nonce is predefined as explained in the original script :
        # trying to avoid sending the authentication key in the "clear" but
        # not wanting to deal with a full digest like exchange. Using a
        # fixed nonce to mix up the limited userid.
        _nonceb64 = "ElWO1arph+Jifqme6eXD8Uj+QTAmijAWxX1msbJzXDM="

        log_output = ""
        for attempt in self.batch:
            log_output += "{}\t{}\t{}\t{}\t{}\t{}\n".format(
                attempt["date"],
                attempt["time"],
                attempt["timezone"],
                attempt["source_ip"],
                attempt["user"],
                attempt["password"],
            )

        nonce = base64.b64decode(_nonceb64)
        digest = base64.b64encode(
            hmac.new(
                nonce + self.userid.encode("ascii"),
                base64.b64decode(self.auth_key),
                hashlib.sha256,
            ).digest()
        )
        auth_header = "credentials={} nonce={} userid={}".format(
            digest.decode("ascii"), _nonceb64, self.userid
        )
        headers = {"X-ISC-Authorization": auth_header, "Content-Type": "text/plain"}

        if self.debug:
            log.msg(f"dshield: posting: {headers!r}")
            log.msg(f"dshield: posting: {log_output}")

        req = threads.deferToThread(
            requests.request,
            method="PUT",
            url="https://secure.dshield.org/api/file/sshlog",
            headers=headers,
            timeout=HTTP_TIMEOUT,
            data=log_output,
        )

        def check_response(resp):
            failed = False
            response = resp.content.decode("utf8")

            if self.debug:
                log.msg(f"dshield: status code {resp.status_code}")
                log.msg(f"dshield: response {resp.content}")

            if resp.ok:
                sha1_regex = re.compile(r"<sha1checksum>([^<]+)<\/sha1checksum>")
                sha1_match = sha1_regex.search(response)
                sha1_local = hashlib.sha1()
                sha1_local.update(log_output.encode("utf8"))
                if sha1_match is None:
                    log.msg(
                        f"dshield: ERROR: Could not find sha1checksum in response: {response!r}"
                    )
                    failed = True
                elif sha1_match.group(1) != sha1_local.hexdigest():
                    log.msg(
                        f"dshield: ERROR: SHA1 Mismatch {sha1_match.group(1)} {sha1_local.hexdigest()} ."
                    )
                    failed = True

                md5_regex = re.compile(r"<md5checksum>([^<]+)<\/md5checksum>")
                md5_match = md5_regex.search(response)
                md5_local = hashlib.md5()
                md5_local.update(log_output.encode("utf8"))
                if md5_match is None:
                    log.msg("dshield: ERROR: Could not find md5checksum in response")
                    failed = True
                elif md5_match.group(1) != md5_local.hexdigest():
                    log.msg(
                        f"dshield: ERROR: MD5 Mismatch {md5_match.group(1)} {md5_local.hexdigest()} ."
                    )
                    failed = True

                log.msg(
                    f"dshield: SUCCESS: Sent {log_output} bytes worth of data to secure.dshield.org"
                )
            else:
                log.msg(f"dshield ERROR: error {resp.status_code}.")
                log.msg(f"dshield response was {response}")
                failed = True

            if failed:
                # Something went wrong, we need to add them to batch.
                reactor.callFromThread(self.transmission_error, batch)

        req.addCallback(check_response)
