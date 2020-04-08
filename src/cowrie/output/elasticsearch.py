# Simple elasticsearch logger

from __future__ import absolute_import, division

from elasticsearch import Elasticsearch

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    elasticsearch output
    """

    def start(self):
        self.host = CowrieConfig().get("output_elasticsearch", "host")
        self.port = CowrieConfig().get("output_elasticsearch", "port")
        self.index = CowrieConfig().get("output_elasticsearch", "index")
        self.type = CowrieConfig().get("output_elasticsearch", "type")
        self.pipeline = CowrieConfig().get("output_elasticsearch", "pipeline")
        # new options (creds + https)
        self.username = CowrieConfig().get("output_elasticsearch", "username")
        self.password = CowrieConfig().get("output_elasticsearch", "password")
        self.use_ssl = CowrieConfig().getboolean(
            "output_elasticsearch", "ssl", fallback=False
        )
        self.ca_certs = CowrieConfig().get("output_elasticsearch", "ca_certs")
        self.verify_certs = CowrieConfig().getboolean(
            "output_elasticsearch", "verify_certs", fallback=True
        )

        options = {}
        # connect
        if (self.username is not None) and (self.password is not None):
            options["http_auth"] = (self.username, self.password)
        if self.use_ssl:
            options["scheme"] = "https"
            options["use_ssl"] = self.use_ssl
            options["ssl_show_warn"] = False
            options["ca_certs"] = self.ca_certs
            options["verify_certs"] = self.verify_certs

        # connect
        self.es = Elasticsearch("{0}:{1}".format(self.host, self.port), **options)
        # self.es = Elasticsearch('{0}:{1}'.format(self.host, self.port))

        self.check_index()

    def check_index(self):
        """
        This function check whether the index exists.
        """
        if not self.es.indices.exists(index=self.index):
            #  create index
            self.es.indices.create(index=self.index)

    def check_geoip_mapping(self):
        """
        This function ensures that the right mapping is set up
        to convert source ip (src_ip) into geo data 
        """
        if self.es.indices.exists(index=self.index):
            # add mapping (to add geo field -> for geoip)
            # the new feature is named 'geo'
            self.es.indices.put_mapping(
                index=self.index,
                body={
                    "properties": {
                        "geo": {"properties": {"location": {"type": "geo_point"}}}
                    }
                },
            )

    def stop(self):
        pass

    def write(self, logentry):
        for i in list(logentry.keys()):
            # remove twisted 15 legacy keys
            if i.startswith("log_"):
                del logentry[i]

        self.es.index(
            index=self.index, doc_type=self.type, body=logentry, pipeline=self.pipeline
        )
