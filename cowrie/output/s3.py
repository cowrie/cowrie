"""
Send downloaded/uplaoded files to S3 (or compatible)
"""

from __future__ import division, absolute_import

import os

from twisted.internet import defer, threads

from botocore.session import get_session
from botocore.exceptions import ClientError

import cowrie.core.output


class Output(cowrie.core.output.Output):

    def __init__(self, cfg):
        self.seen = set()

        self.session = get_session()
        self.session.set_credentials(
            cfg.get("output_s3", "access_key_id"),
            cfg.get("output_s3", "secret_access_key"),
        )
        self.client = self.session.create_client(
            's3',
            region_name=cfg.get("output_s3", "region"),
            endpoint_url=cfg.get("output_s3", "endpoint") or None,
            verify=False if cfg.get("output_s3", "verify") == "no" else True,
        )
        self.bucket = cfg.get("output_s3", "bucket")
        cowrie.core.output.Output.__init__(self, cfg)

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
