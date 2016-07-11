
from twisted.trial import unittest

from cowrie.core.utils import durationHuman


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

