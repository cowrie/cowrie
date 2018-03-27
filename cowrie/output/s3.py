"""
Send downloaded/uplaoded files to S3 (or compatible)
"""

from __future__ import division, absolute_import

import os

from twisted.internet import defer, threads
from twisted.python import log


from botocore.session import get_session
from botocore.exceptions import ClientError

import cowrie.core.output

from cowrie.core.config import CONFIG
from configparser import NoOptionError



class Output(cowrie.core.output.Output):

    def __init__(self):
        self.seen = set()

        self.session = get_session()

        try:
          if CONFIG.get("output_s3", "access_key_id") and CONFIG.get("output_s3", "secret_access_key"):
            self.session.set_credentials(
                CONFIG.get("output_s3", "access_key_id"),
                CONFIG.get("output_s3", "secret_access_key"),
            )
        except NoOptionError:
            log.msg("No AWS credentials found in config - using botocore global settings.")

        self.client = self.session.create_client(
            's3',
            region_name=CONFIG.get("output_s3", "region"),
            endpoint_url=CONFIG.get("output_s3", "endpoint") or None,
            verify=False if CONFIG.get("output_s3", "verify") == "no" else True,
        )
        self.bucket = CONFIG.get("output_s3", "bucket")
        cowrie.core.output.Output.__init__(self)

    def start(self):
        pass

    def stop(self):
        pass

    def write(self, entry):
        if entry["eventid"] == "cowrie.session.file_download":
            self.upload(entry['shasum'], entry["outfile"])

        elif entry["eventid"] == "cowrie.session.file_upload":
            self.upload(entry['shasum'], entry['outfile'])

    @defer.inlineCallbacks
    def _object_exists_remote(self, shasum):
        try:
            yield threads.deferToThread(
                self.client.head_object,
                Bucket=self.bucket,
                Key=shasum,
            )
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                defer.returnValue(False)
            raise

        defer.returnValue(True)

    @defer.inlineCallbacks
    def upload(self, shasum, filename):
        if shasum in self.seen:
            print("Already uploaded file with sha {} to S3".format(shasum))
            return

        exists = yield self._object_exists_remote(shasum)
        if exists:
            print("Somebody else already uploaded file with sha {} to S3".format(shasum))
            self.seen.add(shasum)
            return

        print("Uploading file with sha {} ({}) to S3".format(shasum, filename))
        with open(filename, 'rb') as fp:
            yield threads.deferToThread(
                self.client.put_object,
                Bucket=self.bucket,
                Key=shasum,
                Body=fp.read(),
                ContentType='application/octet-stream',
            )

        self.seen.add(shasum)
