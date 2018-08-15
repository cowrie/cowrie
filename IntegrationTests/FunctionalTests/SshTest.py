import unittest
from paramiko import SSHClient, client, ssh_exception
from IntegrationTests.Helpers.DockerHelper import DockerHelper


class TestSsh(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Create a Container that can be used within the tests.
        """
        cls.container = DockerHelper.get("cowrie-test-ssh")
        cls.container_ip = cls.container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        super(TestSsh, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        """
        Remove our Testcontainerclient.
        """
        cls.container.stop()
        super(TestSsh, cls).tearDownClass()

    def test_LoginIntoSshWithRoot_LoginWillSucceed(self):
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
        ssh_client.connect(self.container_ip, port=2222, username="root", password="foobar")

    def test_LoginIntoSshWithOtherUser_WillRaiseAuthenticationException(self):
        sshClient = SSHClient()
        sshClient.set_missing_host_key_policy(client.AutoAddPolicy)
        self.assertRaises(
            ssh_exception.AuthenticationException,
            lambda: sshClient.connect(self.container_ip, port=2222, username="OtherUser", password="OtherPassword"))
