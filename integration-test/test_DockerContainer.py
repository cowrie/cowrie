import unittest
import docker
import os
import time
import socket
from paramiko import SSHClient, client, ssh_exception
from ddt import ddt, data

@ddt
class test_DockerContainer(unittest.TestCase):

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
        super(test_DockerContainer, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        """
        Remove our Testcontainerclient.
        """
        cls.container.stop()
        super(test_DockerContainer, cls).tearDownClass()

    @data(2222)#, 2223) <- telnet not open yet. activate when the dockerfile supports boths ports
    def test_ConnectToPort_ConnectionResultIsNotZero(self, value):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((self.container_ip, value))
        self.assertEqual(result, 0, f"Port {value} not open.")

    def test_LoginIntoSshWithRoot_LoginWillSucceed(self):
        sshClient = SSHClient()
        sshClient.set_missing_host_key_policy(client.AutoAddPolicy)
        sshClient.connect(self.container_ip, port=2222, username="root", password="foobar")

    def test_LoginIntoSshWithOtherUser_WillRaiseAuthenticationException(self):
        sshClient = SSHClient()
        sshClient.set_missing_host_key_policy(client.AutoAddPolicy)
        self.assertRaises(
            ssh_exception.AuthenticationException,
            lambda : sshClient.connect(self.container_ip, port=2222, username="OtherUser", password="OtherPassword"))