import unittest
import socket

from ddt import ddt, data

import IntegrationTests.Helpers.DockerHelper


@ddt
class TestDockerContainer(unittest.TestCase):
    """
    The docker build is tested implicit as we need a build image to test it.
    """

    container = None

    @classmethod
    def setUpClass(cls):
        """
        Create a Container that can be used within the tests.
        """
        cls.container = IntegrationTests.Helpers.DockerHelper.DockerHelper.get("cowrie-test-dockercontainer")
        cls.container_ip = cls.container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        super(TestDockerContainer, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        """
        Remove our Testcontainerclient.
        """
        cls.container.stop()
        super(TestDockerContainer, cls).tearDownClass()

    @data(2222)  # , 2223) <- telnet not open yet. activate when the dockerfile supports both ports
    def test_ConnectToPort_ConnectionResultIsNotZero(self, value):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((self.container_ip, value))
        self.assertEqual(result, 0, f"Port {value} not open.")
