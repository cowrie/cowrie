# A simple logger to export events to omnisci

from __future__ import absolute_import, division

import cowrie.core.output
from cowrie.core.config import CowrieConfig
import pymapd as pmd


class Output(cowrie.core.output.Output):
    """
    OmniSciDB Output
    """

    def start(self):
        self.host = if CowrieConfig().get('output_omniscidb', 'host') else None
        self.port = if CowrieConfig().get('output_omniscidb', 'port') else None
        self.table = if CowrieConfig().get('output_omniscidb', 'table') else None
        self.protocol = if CowrieConfig().get('output_omniscidb', 'protocol') else None
        self.username = if CowrieConfig().get('output_omniscidb', 'username') else None
        self.password = if CowrieConfig().get('output_omniscidb', 'password') else None
        try:
            self.connection = pmd.connect(user=self.username,
                                          password=self.password,
                                          host=self.host,
                                          dbname=self.table,
                                          protocol=self.protocol,
                                          port=self.port)
        except Exception as e:
            log.msg("output_omniscidb: Error %s" % (e.args[1]))

    def stop(self):
        log.msg("Closing OmniSciDB connection")
        self.connection.close()

    def write(self, entry):
        pass
