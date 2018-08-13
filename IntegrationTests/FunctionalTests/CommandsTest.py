import unittest
from ddt import ddt
from IntegrationTests.Helpers.DockerHelper import DockerHelper


@ddt
class test_Commands(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Create a Container that can be used within the tests.
        """
        cls.container = DockerHelper.get("cowrie-test-commands")
        cls.container_ip = cls.container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        super(test_Commands, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        """
        Remove our Testcontainerclient.
        """
        cls.container.stop()
        super(test_Commands, cls).tearDownClass()
