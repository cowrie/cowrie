from __future__ import absolute_import, division

import os

from twisted.trial import unittest

from cowrie.shell import protocol
from cowrie.test import fake_server, fake_transport

os.environ["HONEYPOT_DATA_PATH"] = "../data"
os.environ["HONEYPOT_FILESYSTEM_FILE"] = "../share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellBaseCommandsTests(unittest.TestCase):

    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(fake_server.FakeAvatar(fake_server.FakeServer()))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def test_whoami_command(self):
        self.proto.lineReceived(b'whoami\n')
        self.assertEqual(self.tr.value(), b'root\n' + PROMPT)

    def test_users_command(self):
        self.proto.lineReceived(b'users \n')
        self.assertEqual(self.tr.value(), b'root\n' + PROMPT)

    def test_hostname_command(self):
        self.proto.lineReceived(b'hostname unitChanged\n')
        self.assertEquals(self.tr.value(), b'root@unitChanged:~# ')

    def test_id_command(self):
        self.proto.lineReceived(b'id\n')
        self.assertEquals(self.tr.value(), b'uid=0(root) gid=0(root) groups=0(root)\n' + PROMPT)

    def test_passwd_command(self):
        self.proto.lineReceived(b'passwd\n')
        self.proto.lineReceived(b'changeme\n')
        self.proto.lineReceived(b'changeme\n')
        self.assertEquals(
            self.tr.value(),
            b'Enter new UNIX password: Retype new UNIX password: passwd: password updated successfully\n' + PROMPT)

    def test_date_command(self):
        self.proto.lineReceived(b'date\n')
        self.assertRegexpMatches(
            self.tr.value(),
            b'[A-Za-z][A-Za-z][A-Za-z] [A-Za-z][A-Za-z][A-Za-z] [0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] UTC [0-9][0-9][0-9][0-9]\n' + PROMPT)  # noqa: E501

    def test_sh_command(self):
        self.proto.lineReceived(b'sh -c id\n')
        self.assertEquals(self.tr.value(), b'uid=0(root) gid=0(root) groups=0(root)\n' + PROMPT)

    def test_chattr_command(self):
        self.proto.lineReceived(b'chattr\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_umask_command(self):
        self.proto.lineReceived(b'umask\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_set_command(self):
        self.proto.lineReceived(b'set\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_unset_command(self):
        self.proto.lineReceived(b'unset\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_export_command(self):
        self.proto.lineReceived(b'export\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_alias_command(self):
        self.proto.lineReceived(b'alias\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_jobs_command(self):
        self.proto.lineReceived(b'jobs\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_kill_command(self):
        self.proto.lineReceived(b'/bin/kill\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_pkill_command(self):
        self.proto.lineReceived(b'/bin/pkill\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_killall_command(self):
        self.proto.lineReceived(b'/bin/killall\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_killall5_command(self):
        self.proto.lineReceived(b'/bin/killall5\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_su_command(self):
        self.proto.lineReceived(b'su\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_chown_command(self):
        self.proto.lineReceived(b'chown\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_chgrp_command(self):
        self.proto.lineReceived(b'chgrp\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")


class ShellFileCommandsTests(unittest.TestCase):
    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(
            fake_server.FakeAvatar(fake_server.FakeServer()))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")


class ShellPipeCommandsTests(unittest.TestCase):

    def setUp(self):
        self.proto = protocol.HoneyPotInteractiveProtocol(
            fake_server.FakeAvatar(fake_server.FakeServer()))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)

    def test_shell_pipe_with_cat_tail(self):
        self.proto.lineReceived(b'echo test | tail -n 1\n')
        self.assertEquals(self.tr.value(), PROMPT + b'test\n' + PROMPT)

    def test_shell_pipe_with_cat_head(self):
        self.proto.lineReceived(b'echo test | head -n 1\n')
        self.assertEquals(self.tr.value(), PROMPT + b'test\n' + PROMPT)

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
