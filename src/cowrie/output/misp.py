from io import BytesIO

from pymisp import ExpandedPyMISP, MISPEvent, MISPSighting
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

class Output(cowrie.core.output.Output):
    """
    MISP Upload Plugin for Cowrie.

    This Plugin creates a new event for unseen file uploads
    or adds sightings for previously seen files.
    """

    def start(self):
        """
        Start output plugin
        """
        misp_url = CowrieConfig().get('output_misp', 'base_url')
        misp_key = CowrieConfig().get('output_misp', 'api_key')
        misp_verifycert = ("true" == CowrieConfig().get('output_misp', 'verify_cert').lower())
        self.misp_api = ExpandedPyMISP(url=misp_url, key=misp_key, ssl=misp_verifycert, debug=False)


    def stop(self):
        """
        Stop output plugin
        """
        pass


    def write(self, entry):
        """
        Do something 
        """
        if entry['eventid'] == 'cowrie.session.file_download':
            file_sha_attrib = self.find_attribute("sha256", entry["shasum"])
            if file_sha_attrib:
                # file is known, add sighting!
                log.msg("File known, add sighting!")
                self.add_sighting(entry, file_sha_attrib)
            else:
                # file is unknown, new event with upload
                log.msg("File unknwon, add new event!")
                self.create_new_event(entry)


    def find_attribute(self, attribute_type, searchterm):
        result = self.misp_api.search(
            controller="attributes",
            type_attribute=attribute_type,
            value=searchterm
        )
        if result["Attribute"]:
            return result["Attribute"][0]
        else:
            return None


    def create_new_event(self, entry):
        self.misp_api.upload_sample(
            entry["shasum"],
            entry["outfile"],
            None,
            distribution=1,
            info="Uploaded by: {} (Cowrie)".format(entry["sensor"]),
            analysis=0,
            threat_level_id=2
        )


    def add_sighting(self, entry, attribute):
        sighting = MISPSighting()
        sighting.source = "{} (Cowrie)".format(entry["sensor"])
        self.misp_api.add_sighting(sighting, attribute)
