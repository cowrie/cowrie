from __future__ import division, absolute_import

import ConfigParser
import io
import textwrap

from twisted.application.service import MultiService
from twisted.internet import protocol, reactor
from twisted.trial import unittest

from cowrie.core.utils import durationHuman, get_endpoints_from_section, create_endpoint_services


def get_config(config_string):
    config = ConfigParser.RawConfigParser()
    config.readfp(io.BytesIO(textwrap.dedent(config_string)))
    return config


class UtilsTestCase(unittest.TestCase):
    """
    Tests for cowrie/core/utils.py
    """

    def test_durationHuman(self):
        """
        Test of cowrie.core.utils.durationHuman
        """
        minute = durationHuman(60)
        self.assertEqual(minute, "01:00")
        hour = durationHuman(3600)
        self.assertEqual(hour, "01:00:00")
        something = durationHuman(364020)
        self.assertEqual(something, "4.0 days 05:07:00")

    def test_get_endpoints_from_section(self):
        cfg = get_config(b"""
            [ssh]
            listen_addr = 1.1.1.1
        """)
        self.assertEqual(["tcp:2223:interface=1.1.1.1"], get_endpoints_from_section(cfg, "ssh", 2223))

        cfg = get_config(b"""
            [ssh]
            listen_addr = 1.1.1.1
        """)
        self.assertEqual(["tcp:2224:interface=1.1.1.1"], get_endpoints_from_section(cfg, "ssh", 2224))

        cfg = get_config(b"""
            [ssh]
            listen_addr = 1.1.1.1 2.2.2.2
        """)
        self.assertEqual(["tcp:2223:interface=1.1.1.1", "tcp:2223:interface=2.2.2.2"], get_endpoints_from_section(cfg, "ssh", 2223))

        cfg = get_config(b"""
            [ssh]
            listen_addr = 1.1.1.1 2.2.2.2
            listen_port = 23
        """)
        self.assertEqual(["tcp:23:interface=1.1.1.1", "tcp:23:interface=2.2.2.2"], get_endpoints_from_section(cfg, "ssh", 2223))

        cfg = get_config(b"""
            [ssh]
            listen_endpoints = tcp:23:interface=1.1.1.1 tcp:2323:interface=1.1.1.1
        """)
        self.assertEqual(["tcp:23:interface=1.1.1.1", "tcp:2323:interface=1.1.1.1"], get_endpoints_from_section(cfg, "ssh", 2223))

    def test_create_endpoint_services(self):
        parent = MultiService()
        create_endpoint_services(reactor, parent, [b"tcp:23:interface=1.1.1.1"], protocol.Factory())
        self.assertEqual(len(parent.services), 1)

        parent = MultiService()
        create_endpoint_services(reactor, parent, [u"tcp:23:interface=1.1.1.1"], protocol.Factory())
        self.assertEqual(len(parent.services), 1)

        parent = MultiService()
        create_endpoint_services(reactor, parent, ["tcp:23:interface=1.1.1.1", "tcp:2323:interface=2.2.2.2"], protocol.Factory())
        self.assertEqual(len(parent.services), 2)
