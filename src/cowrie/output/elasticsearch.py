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
        self.host = CowrieConfig().get('output_elasticsearch', 'host')
        self.port = CowrieConfig().get('output_elasticsearch', 'port')
        self.index = CowrieConfig().get('output_elasticsearch', 'index')
        self.type = CowrieConfig().get('output_elasticsearch', 'type')
        self.pipeline = CowrieConfig().get('output_elasticsearch', 'pipeline')
        self.es = Elasticsearch('{0}:{1}'.format(self.host, self.port))

    def stop(self):
        pass

    def write(self, logentry):
        for i in list(logentry.keys()):
            # remove twisted 15 legacy keys
            if i.startswith('log_'):
                del logentry[i]

        self.es.index(index=self.index, doc_type=self.type, body=logentry, pipeline=self.pipeline)
