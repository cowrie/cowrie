import re
import time
import unittest
from os import listdir, path

from ddt import ddt, idata
from paramiko import SSHClient, AutoAddPolicy

from IntegrationTests.Helpers.DockerHelper import DockerHelper


def getCommands():
    regex = re.compile(r"commands\['([^\']*)'\]")
    for filename in listdir("src/cowrie/commands"):
        filepath = f'src/cowrie/commands/{filename}'
        if path.isfile(filepath):
            file_string = open(filepath, 'r').read()
            commands = regex.findall(file_string)
            for command in commands:
                yield command


@ddt
class TestCommands(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """
        Create a Container that can be used within the tests.
        """
        cls.container = DockerHelper.get("cowrie-test-commands")
        cls.container_ip = cls.container.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]

        cls.sshClient = SSHClient()
        cls.sshClient.set_missing_host_key_policy(AutoAddPolicy())
        cls.sshClient.connect(cls.container_ip, port=2222, username="root", password="foobar")
        super(TestCommands, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        """
        Remove our Testcontainerclient.
        """
        cls.sshClient.close()
        cls.container.stop()
        super(TestCommands, cls).tearDownClass()

    def runShellCommand(self, command):
        transport = self.sshClient.get_transport()
        shell = transport.open_session(timeout=30)
        shell.invoke_shell()
        shell.get_pty()
        shell.send(f"{command}\n")
        shell.close()

    @idata(getCommands())
    def test_execute(self, command):
        test_start_time = int(time.time())
        self.runShellCommand(command)

        log_lines = ""
        while log_lines.find(f"found: {command}") == -1:
            log_lines = self.container.logs(since=test_start_time, until=int(time.time()), tail=all).decode()

        self.assertEqual(
            -1, log_lines.find("Traceback ("),
            f"Failed running command {command} -  Logs: \n {log_lines}")
        self.assertNotEqual(
            -1, log_lines.find(f"Command found: {command}"),
            f"Failed running command {command} - exit"
            f"Logs: \n {log_lines}")

