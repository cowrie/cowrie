# -*- test-case-name: Cowrie Test Cases -*-

# Copyright (c) 2016 Dave Germiquet
# See LICENSE for details.

from __future__ import division, absolute_import

from twisted.trial import unittest

from cowrie.core import protocol
from cowrie.core import config
from cowrie.test import fake_server, fake_transport
import json



class ShellBaseCommandsTests(unittest.TestCase):


    def setUp(self):
        with open('../cowrie/test/expected_results.json') as data_file:
            self.data = json.load(data_file)
        self.cfg = config.readConfigFile("../cowrie/test/unittests.cfg")
        self.proto = protocol.HoneyPotInteractiveProtocol \
            (fake_server.FakeAvatar(fake_server.FakeServer(self.cfg)))
        self.tr = fake_transport.FakeTransport("1.1.1.1", "1111")
        self.proto.makeConnection(self.tr)
        self.tr.clear()


    def test_whoami_command(self):
        self.proto.lineReceived('whoami \n')
        self.assertEqual(self.tr.value(),self.data['results']['whoami'])


    def test_users_command(self):
        self.proto.lineReceived('users \n')
        self.assertEqual(self.tr.value(),self.data['results']['users'])


    def test_help_command(self):
        self.proto.lineReceived('help \n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['help']))

    def test_w_command(self):
        self.proto.lineReceived('w \n')
        self.assertRegexpMatches(self.tr.value(),("\n").join(self.data['results']['w']))


    def test_who_command(self):
        self.proto.lineReceived('who \n')
        self.assertRegexpMatches(self.tr.value(),"\n".join(self.data['results']['who']))


    def test_echo_command(self):
        self.proto.lineReceived('echo "test worked correctly" \n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['echo']))


    def test_exit_command(self):
        self.proto.lineReceived('exit \n')


    def test_logout_command(self):
        self.proto.lineReceived('logout \n')


    def test_clear_command(self):
        self.proto.lineReceived('clear \n')


    def test_hostname_command(self):
        self.proto.lineReceived('hostname unitChanged\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['hostname']))


    def test_reset_command(self):
        self.proto.lineReceived('reset')


    def test_ps_command(self):
        self.proto.lineReceived('ps\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['ps']))

    def test_id_command(self):
        self.proto.lineReceived('id\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['id']))


    def test_passwd_command(self):
        self.proto.lineReceived('passwd\n')
        self.proto.lineReceived('changeme\n')
        self.proto.lineReceived('changeme\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['passwd']))


    def test_shutdown_command(self):
        self.proto.lineReceived('shutdown\n')


    def test_poweroff_command(self):
        self.proto.lineReceived('poweroff\n')


    def test_history_command(self):
        self.proto.lineReceived("history\n")
        self.proto.lineReceived("history\n")
        # Not Sure HOW TO TEST THIS!!
        print(self.tr.value())


    def test_date_command(self):
        self.proto.lineReceived('date\n')
        self.assertRegexpMatches(self.tr.value(),("\n").join(self.data['results']['date']))


    def test_bash_command(self):
        self.proto.lineReceived('bash\n')


    def test_sh_command(self):
        self.proto.lineReceived('sh -c who\n')
        self.assertRegexpMatches(self.tr.value(),"\n".join(self.data['results']['who']))


    def test_php_command(self):
        self.proto.lineReceived('php -h')
        print(self.tr.value())



    def test_chattr_command(self):
        self.proto.lineReceived('chattr\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['chattr']))


    def test_umask_command(self):
        self.proto.lineReceived('umask\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['umask']))


    def test_set_command(self):
        self.proto.lineReceived('set\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['set']))


    def test_unset_command(self):
        self.proto.lineReceived('unset\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['unset']))


    def test_export_command(self):
        self.proto.lineReceived('export\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['export']))


    def test_alias_command(self):
        self.proto.lineReceived('alias\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['alias']))


    def test_jobs_command(self):
        self.proto.lineReceived('jobs\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['jobs']))


    def test_kill_command(self):
        self.proto.lineReceived('/bin/kill\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['kill']))


    def test_pkill_command(self):
        self.proto.lineReceived('/bin/pkill\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['kill']))


    def test_killall_command(self):
        self.proto.lineReceived('/bin/killall\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['kill']))


    def test_killall5_command(self):
        self.proto.lineReceived('/bin/killall5\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['kill']))


    def test_su_command(self):
        self.proto.lineReceived('su\n')
        self.assertEquals(self.tr.value(),"\67n".join(self.data['results']['su']))

    def test_chown_command(self):
        self.proto.lineReceived('chown\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['chown']))


    def test_chgrp_command(self):
        self.proto.lineReceived('chgrp\n')
        self.assertEquals(self.tr.value(),"\n".join(self.data['results']['chgrp']))


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

