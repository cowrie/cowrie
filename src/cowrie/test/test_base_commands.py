# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2016 Dave Germiquet
# See LICENSE for details.

from __future__ import absolute_import, division

import os

from twisted.trial import unittest

from cowrie.shell import protocol
from cowrie.test import fake_server, fake_transport

os.environ["HONEYPOT_DATA_PATH"] = "../data"
os.environ["SHELL_FILESYSTEM"] = "../share/cowrie/fs.pickle"

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

    # def test_exit_command(self):
    #     self.proto.lineReceived(b'exit \n')

    # def test_logout_command(self):
    #     self.proto.lineReceived(b'logout \n')

    # def test_clear_command(self):
    #     self.proto.lineReceived(b'clear \n')

    def test_hostname_command(self):
        self.proto.lineReceived(b'hostname unitChanged\n')
        self.assertEquals(self.tr.value(), b'root@unitChanged:~# ')

    # def test_reset_command(self):
    #     self.proto.lineReceived(b'reset')

    # def test_ps_command(self):
    #     self.proto.lineReceived(b'ps\n')
    #     self.assertEquals(self.tr.value().decode('utf8'), "\n".join(self.data['results']['ps']))

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

    # def test_shutdown_command(self):
    #    self.proto.lineReceived(b'shutdown\n')

    # def test_poweroff_command(self):
    #     self.proto.lineReceived(b'poweroff\n')

    # def test_history_command(self):
    #    self.proto.lineReceived(b"history\n")
    #    self.proto.lineReceived(b"history\n")
    #    print("THIS TEST IS INCOMPLETE")

    def test_date_command(self):
        self.proto.lineReceived(b'date\n')
        self.assertRegex(
            self.tr.value(),
            b'[A-Za-z][A-Za-z][A-Za-z] [A-Za-z][A-Za-z][A-Za-z] [0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9] UTC [0-9][0-9][0-9][0-9]\n' + PROMPT)  # noqa: E501

    # def test_bash_command(self):
    #    self.proto.lineReceived(b'bash\n')
    #    print("THIS TEST IS INCOMPLETE")

    def test_sh_command(self):
        self.proto.lineReceived(b'sh -c id\n')
        self.assertEquals(self.tr.value(), b'uid=0(root) gid=0(root) groups=0(root)\n' + PROMPT)

    # def test_php_command(self):
    #    self.proto.lineReceived(b'php -h')
    #    print("THIS TEST IS INCOMPLETE")

    def test_chattr_command(self):
        self.proto.lineReceived(b'chattr\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_umask_command(self):
        self.proto.lineReceived(b'umask\n')
        self.assertEquals(self.tr.value(), PROMPT)

    def test_set_command(self):
        self.proto.lineReceived(b'set\n')

        self.assertEquals(
            self.tr.value(),
            b'COLUMNS=80\nHOME=/root\nLINES=25\nLOGNAME=root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nTMOUT=1800\nUSER=root\n' + PROMPT)  # noqa: E501

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

    # def test_cat_output(self):
    #    self.proto.lineReceived(b'cat /proc/cpuinfo')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_grep_output(self):
    #    self.proto.lineReceived(b'grep cpu /proc/cpuinfo')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_tail_output(self):
    #    self.proto.lineReceived(b'tail -n 10 /proc/cpuinfo')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_cd_output(self):
    #    self.proto.lineReceived(b'cd /usr/bin')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_rm_output(self):
    #    self.proto.lineReceived(b'rm /usr/bin/gcc')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_cp_output(self):
    #    self.proto.lineReceived(b'cp /usr/bin/gcc /tmp')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_mv_output(self):
    #    self.proto.lineReceived(b'mv /usr/bin/gcc /tmp')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_mkdir_output(self):
    #    self.proto.lineReceived(b'mkdir /tmp/hello')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_rmdir_output(self):
    #    self.proto.lineReceived(b'mkdir /tmp/blah')
    #    self.proto.lineReceived(b'rmdir /tmp/blah')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_pwd_output(self):
    #    self.proto.lineReceived(b'pwd')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

    # def test_touch_output(self):
    #    self.proto.lineReceived(b'touch unittests.txt')
    #    print("THIS TEST IS INCOMPLETE")
    #    print(self.tr.value())

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

    # def test_shell_busybox_with_cat_and_sudo_grep(self):
    #     self.proto.lineReceived(b'busybox cat /proc/cpuinfo | sudo grep cpu \n')

    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")
