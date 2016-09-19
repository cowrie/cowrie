# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2016 Dave Germiquet
# See LICENSE for details.

from twisted.trial import unittest

from cowrie.core import protocol
from cowrie.core import config
from . import fake_server
from . import fake_transport


class ShellBaseCommandsTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.readConfigFile("../cowrie/test/unittests.cfg")
        self.proto = protocol.HoneyPotInteractiveProtocol \
            (fake_server.FakeAvatar(fake_server.FakeServer(self.cfg)))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)


    def test_whoami_command(self):
        self.proto.lineReceived('whoami \n')
        print(self.tr.value())


    def test_users_command(self):
        self.proto.lineReceived('users \n')
        print(self.tr.value())


    def test_help_command(self):
        self.proto.lineReceived('help \n')
        print(self.tr.value())


    def test_w_command(self):
        self.proto.lineReceived('w \n')
        print(self.tr.value())


    def test_who_command(self):
        self.proto.lineReceived('who \n')
        print(self.tr.value())


    def test_echo_command(self):
        self.proto.lineReceived('echo "test worked correctly" \n')
        print(self.tr.value())


    def test_exit_command(self):
        self.proto.lineReceived('exit \n')
        print(self.tr.value())


    def test_logout_command(self):
        self.proto.lineReceived('logout \n')
        print(self.tr.value())


    def test_clear_command(self):
        self.proto.lineReceived('clear \n')
        print(self.tr.value())


    def test_reset_command(self):
        self.proto.lineReceived('hostname unitChanged\n')
        print(self.tr.value())


    def test_hostname_command(self):
        self.proto.lineReceived('hostname unitChanged\n')
        print(self.tr.value())


    def test_ps_command(self):
        self.proto.lineReceived('ps\n')
        print(self.tr.value())


    def test_id_command(self):
        self.proto.lineReceived('id\n')
        print(self.tr.value())


    def test_passwd_command(self):
        self.proto.lineReceived('passwd\n')
        self.proto.lineReceived('changeme\n')
        self.proto.lineReceived('changeme\n')
        print(self.tr.value())


    def test_shutdown_command(self):
        self.proto.lineReceived('shutdown\n')
        print(self.tr.value())


    def test_poweroff_command(self):
        self.proto.lineReceived('poweroff\n')
        print(self.tr.value())


    def test_history_command(self):
        self.proto.lineReceived('history\n')
        print(self.tr.value())


    def test_date_command(self):
        self.proto.lineReceived('date\n')
        print(self.tr.value())


    def test_bash_command(self):
        self.proto.lineReceived('bash\n')
        print(self.tr.value())


    def test_sh_command(self):
        self.proto.lineReceived('sh\n')
        print(self.tr.value())


    def test_php_command(self):
        self.proto.lineReceived('php\n')
        print(self.tr.value())


    def test_chattr_command(self):
        self.proto.lineReceived('chattr\n')
        print(self.tr.value())


    def test_umask_command(self):
        self.proto.lineReceived('umask\n')
        print(self.tr.value())


    def test_set_command(self):
        self.proto.lineReceived('set\n')
        print(self.tr.value())


    def test_unset_command(self):
        self.proto.lineReceived('unset\n')
        print(self.tr.value())


    def test_export_command(self):
        self.proto.lineReceived('export\n')
        print(self.tr.value())


    def test_alias_command(self):
        self.proto.lineReceived('alias\n')
        print(self.tr.value())


    def test_jobs_command(self):
        self.proto.lineReceived('jobs\n')
        print(self.tr.value())


    def test_kill_command(self):
        self.proto.lineReceived('/bin/kill\n')
        print(self.tr.value())


    def test_pkill_command(self):
        self.proto.lineReceived('/bin/pkill\n')
        print(self.tr.value())


    def test_killall_command(self):
        self.proto.lineReceived('/bin/killall\n')
        print(self.tr.value())


    def test_killall5_command(self):
        self.proto.lineReceived('/bin/killall5\n')
        print(self.tr.value())


    def test_su_command(self):
        self.proto.lineReceived('su\n')
        print(self.tr.value())


    def test_chown_command(self):
        self.proto.lineReceived('chown\n')
        print(self.tr.value())


    def test_chgrp_command(self):
        self.proto.lineReceived('chgrp\n')
        print(self.tr.value())


    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")


class ShellFileCommandsTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.readConfigFile("../cowrie/test/unittests.cfg")
        self.proto = protocol.HoneyPotInteractiveProtocol(
            fake_server.FakeAvatar(fake_server.FakeServer(self.cfg)))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)


    def test_cat_output(self):
        self.proto.lineReceived('cat /proc/cpuinfo')
        print(self.tr.value())


    def test_grep_output(self):
        self.proto.lineReceived('grep cpu /proc/cpuinfo')
        print(self.tr.value())


    def test_tail_output(self):
        self.proto.lineReceived('tail -n 10 /proc/cpuinfo')
        print(self.tr.value())


    def test_head_output(self):
        self.proto.lineReceived('head -n 10 /proc/cpuinfo')
        print(self.tr.value())


    def test_cd_output(self):
        self.proto.lineReceived('cd /usr/bin')
        print(self.tr.value())


    def test_rm_output(self):
        self.proto.lineReceived('rm /usr/bin/gcc')
        print(self.tr.value())


    def test_cp_output(self):
        self.proto.lineReceived('cp /usr/bin/gcc /tmp')
        print(self.tr.value())


    def test_mv_output(self):
        self.proto.lineReceived('mv /usr/bin/gcc /tmp')
        print(self.tr.value())


    def test_mkdir_output(self):
        self.proto.lineReceived('mkdir /tmp/hello')
        print(self.tr.value())


    def test_rmdir_output(self):
        self.proto.lineReceived('mkdir /tmp/blah')
        self.proto.lineReceived('rmdir /tmp/blah')
        print(self.tr.value())


    def test_pwd_output(self):
        self.proto.lineReceived('pwd')
        print(self.tr.value())

    def test_netstat_outputa(self):
        self.proto.lineReceived('netstat -a')
        print(self.tr.value())

    def test_netstat_outputn(self):
        self.proto.lineReceived('netstat -n')
        print(self.tr.value())

    def test_netstat_outputl(self):
        self.proto.lineReceived('netstat -l')
        print(self.tr.value())

    def test_touch_output(self):
        self.proto.lineReceived('touch unittests.txt')
        print(self.tr.value())


    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")


class ShellPipeCommandsTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config.readConfigFile("../cowrie/test/unittests.cfg")
        self.proto = protocol.HoneyPotInteractiveProtocol(
            fake_server.FakeAvatar(fake_server.FakeServer(self.cfg)))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)


    def test_shell_pipe_with_ls_tail(self):
        self.proto.lineReceived('ls -la | tail -n 2\n')
        print(self.tr.value())


    def test_shell_pipe_with_cat_head(self):
        self.proto.lineReceived('cat /proc/cpuinfo | head -n 5 \n')
        print(self.tr.value())


    def test_shell_busybox_with_cat_and_sudo_grep(self):
        self.proto.lineReceived('busybox cat /proc/cpuinfo | sudo grep cpu \n')


    def tearDown(self):
        self.proto.connectionLost("tearDown From Unit Test")

