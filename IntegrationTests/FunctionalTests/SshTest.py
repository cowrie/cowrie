import unittest
from paramiko import SSHClient, client, ssh_exception
from ddt import ddt
from IntegrationTests.Helpers.DockerHelper import DockerHelper


@ddt
class test_Ssh(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Create a Container that can be used within the tests.
        """
        cls.container = DockerHelper.get("cowrie-test-ssh")
        cls.container_ip = cls.container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        super(test_Ssh, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        """
        Remove our Testcontainerclient.
        """
        cls.container.stop()
        super(test_Ssh, cls).tearDownClass()

    def test_LoginIntoSshWithRoot_LoginWillSucceed(self):
        sshClient = SSHClient()
        sshClient.set_missing_host_key_policy(client.AutoAddPolicy)
        sshClient.connect(self.container_ip, port=2222, username="root", password="foobar")

    def test_LoginIntoSshWithOtherUser_WillRaiseAuthenticationException(self):
        sshClient = SSHClient()
        sshClient.set_missing_host_key_policy(client.AutoAddPolicy)
        self.assertRaises(
            ssh_exception.AuthenticationException,
            lambda: sshClient.connect(self.container_ip, port=2222, username="OtherUser", password="OtherPassword"))
