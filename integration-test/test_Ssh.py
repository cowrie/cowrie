import unittest
import docker
import os
import time
from paramiko import SSHClient, client, ssh_exception
from ddt import ddt


@ddt
class test_Ssh(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Create a Container that can be used within the tests.
        """
        dockerClient = docker.from_env()
        dockerClient.images.build(
            path=os.getcwd(), tag="testdockercontainerimage")
        cls.container = dockerClient.containers.run(
            image="testdockercontainerimage", name="testdockercontainercontainer",
            detach=True, remove=True)
        cls.container.reload()
        cls.container_ip = cls.container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        time.sleep(10)
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
