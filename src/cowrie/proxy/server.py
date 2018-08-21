from __future__ import absolute_import, division

from cowrie.core.config import CONFIG


class CowrieServer(object):
    """
    In traditional Kippo each connection gets its own simulated machine.
    This is not always ideal, sometimes two connections come from the same
    source IP address. we want to give them the same environment as well.
    So files uploaded through SFTP are visible in the SSH session.
    This class represents a 'virtual server' that can be shared between
    multiple Cowrie connections
    """

    def __init__(self):
        self.avatars = []
        self.hostname = CONFIG.get('honeypot', 'hostname')
