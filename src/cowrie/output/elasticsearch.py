# Simple elasticsearch logger

from __future__ import annotations

from typing import Any

from elasticsearch import Elasticsearch, NotFoundError

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    elasticsearch output
    """

    index: str
    pipeline: str
    es: Any

    def start(self):
        host = CowrieConfig.get("output_elasticsearch", "host")
        port = CowrieConfig.get("output_elasticsearch", "port")
        self.index = CowrieConfig.get("output_elasticsearch", "index")
        self.type = CowrieConfig.get("output_elasticsearch", "type")
        self.pipeline = CowrieConfig.get("output_elasticsearch", "pipeline")
        # new options (creds + https)
        username = CowrieConfig.get("output_elasticsearch", "username", fallback=None)
        password = CowrieConfig.get("output_elasticsearch", "password", fallback=None)
        use_ssl = CowrieConfig.getboolean("output_elasticsearch", "ssl", fallback=False)
        ca_certs = CowrieConfig.get("output_elasticsearch", "ca_certs", fallback=None)
        verify_certs = CowrieConfig.getboolean(
            "output_elasticsearch", "verify_certs", fallback=True
        )

        options: dict[str, Any] = {}
        # connect
        if (username is not None) and (password is not None):
            options["http_auth"] = (username, password)
        if use_ssl:
            options["scheme"] = "https"
            options["use_ssl"] = use_ssl
            options["ssl_show_warn"] = False
            options["verify_certs"] = verify_certs
            if verify_certs:
                options["ca_certs"] = ca_certs

        # connect
        self.es = Elasticsearch(f"{host}:{port}", **options)
        # self.es = Elasticsearch('{0}:{1}'.format(self.host, self.port))

        self.check_index()

        # ensure geoip pipeline is well set up
        if self.pipeline == "geoip":
            # create a new feature if it does not exist yet
            self.check_geoip_mapping()
            # ensure the geoip pipeline is setup
            self.check_geoip_pipeline()

    def check_index(self):
        """
        This function check whether the index exists.
        """
        if not self.es.indices.exists(index=self.index):
            # create index
            self.es.indices.create(index=self.index)

    def check_geoip_mapping(self):
        """
        This function ensures that the right mapping is set up
        to convert source ip (src_ip) into geo data.
        """
        if self.es.indices.exists(index=self.index):
            # Add mapping (to add geo field -> for geoip)
            # The new feature is named 'geo'.
            # You can put mappings several times, if it exists the
            # PUT requests will be ignored.
            self.es.indices.put_mapping(
                index=self.index,
                body={
                    "properties": {
                        "geo": {"properties": {"location": {"type": "geo_point"}}}
                    }
                },
            )

    def check_geoip_pipeline(self):
        """
        This function aims to set at least a geoip pipeline
        to map IP to geo locations
        """
        try:
            # check if the geoip pipeline exists. An error
            # is raised if the pipeline does not exist
            self.es.ingest.get_pipeline(id=self.pipeline)
        except NotFoundError:
            # geoip pipeline
            body = {
                "description": "Add geoip info",
                "processors": [
                    {
                        "geoip": {
                            "field": "src_ip",  # input field of the pipeline (source address)
                            "target_field": "geo",  # output field of the pipeline (geo data)
                            "database_file": "GeoLite2-City.mmdb",
                        }
                    }
                ],
            }
            self.es.ingest.put_pipeline(id=self.pipeline, body=body)

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
