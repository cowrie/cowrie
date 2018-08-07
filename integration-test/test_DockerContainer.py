import unittest
import docker
import os
import time
import socket


class test_DockerContainer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        dockerClient = docker.from_env()
        dockerClient.images.build(
            path=os.getcwd(), tag="testdockercontainerimage")
        dockerClient.containers.run(
            detach=True, remove=True, name="testdockercontainerccontainer",
            image="testdockercontainerimage", ports={"22222": "2222"})
        super(test_DockerContainer, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        dockerClient = docker.from_env()
        dockerClient.containers.get("testdockercontainerccontainer").kill()
        super(test_DockerContainer, cls).tearDownClass()

    def test_RunContainer(self):
        time.sleep(5)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', 22222))
        self.assertNotEqual(result, 0)
