# Copyright (c) 2016 Dave Germiquet
# See LICENSE for details.
from __future__ import annotations

import os
import unittest

from cowrie.commands.base import Command_php
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "
NONEXISTEN_FILE = "/path/to/the/file/that/does/not/exist"


class ShellBaseCommandsTests(unittest.TestCase):  # TODO: ps, history
    """Tests for basic commands from cowrie/commands/base.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_whoami_command(self) -> None:
        self.proto.lineReceived(b"whoami\n")
        self.assertEqual(self.tr.value(), b"root\n" + PROMPT)

    def test_users_command(self) -> None:
        self.proto.lineReceived(b"users \n")
        self.assertEqual(self.tr.value(), b"root\n" + PROMPT)

    def test_exit_command(self) -> None:
        self.proto.lineReceived(b"exit\n")
        self.assertEqual(self.tr.value(), b"")

    def test_logout_command(self) -> None:
        self.proto.lineReceived(b"logout\n")
        self.assertEqual(self.tr.value(), b"")

    def test_clear_command(self) -> None:
        self.proto.lineReceived(b"clear\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_hostname_command(self) -> None:
        self.proto.lineReceived(b"hostname unitChanged\n")
        self.assertEqual(self.tr.value(), b"root@unitChanged:~# ")

    def test_reset_command(self) -> None:
        self.proto.lineReceived(b"reset\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_id_command(self) -> None:
        self.proto.lineReceived(b"id\n")
        self.assertEqual(
            self.tr.value(), b"uid=0(root) gid=0(root) groups=0(root)\n" + PROMPT
        )

    def test_passwd_command(self) -> None:
        self.proto.lineReceived(b"passwd\n")
        self.proto.lineReceived(b"changeme\n")
        self.proto.lineReceived(b"changeme\n")
        self.assertEqual(
            self.tr.value(),
            b"Enter new UNIX password: Retype new UNIX password: passwd: password updated successfully\n"
            + PROMPT,
        )

    def test_shutdown_command(self) -> None:
        self.proto.lineReceived(b"shutdown\n")
        self.assertEqual(
            self.tr.value(), b"Try `shutdown --help' for more information.\n" + PROMPT
        )  # TODO: Is it right?..

    def test_poweroff_command(self) -> None:
        self.proto.lineReceived(b"poweroff\n")
        self.assertEqual(
            self.tr.value(), b"Try `shutdown --help' for more information.\n" + PROMPT
        )  # TODO: Is it right?..

    def test_date_command(self) -> None:
        self.proto.lineReceived(b"date\n")
        self.assertRegex(
            self.tr.value(),
            rb"[A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2} UTC \d{4}\n" + PROMPT,
        )

    def test_bash_command(self) -> None:
        self.proto.lineReceived(b"bash\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_sh_command(self) -> None:
        self.proto.lineReceived(b"sh -c id\n")
        self.assertEqual(
            self.tr.value(), b"uid=0(root) gid=0(root) groups=0(root)\n" + PROMPT
        )

    def test_php_help_command(self) -> None:
        self.proto.lineReceived(b"php -h\n")
        self.assertEqual(self.tr.value(), Command_php.HELP.encode() + PROMPT)

    def test_php_version_command(self) -> None:
        self.proto.lineReceived(b"php -v\n")
        self.assertEqual(self.tr.value(), Command_php.VERSION.encode() + PROMPT)

    def test_chattr_command(self) -> None:
        self.proto.lineReceived(b"chattr\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_umask_command(self) -> None:
        self.proto.lineReceived(b"umask\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_set_command(self) -> None:
        self.proto.lineReceived(b"set\n")
        self.assertEqual(
            self.tr.value(),
            b"COLUMNS=80\nHOME=/root\nLINES=25\nLOGNAME=root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nTMOUT=1800\nUSER=root\n"
            + PROMPT,
        )

    def test_unset_command(self) -> None:
        self.proto.lineReceived(b"unset\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_export_command(self) -> None:
        self.proto.lineReceived(b"export\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_alias_command(self) -> None:
        self.proto.lineReceived(b"alias\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_jobs_command(self) -> None:
        self.proto.lineReceived(b"jobs\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_kill_command(self) -> None:
        self.proto.lineReceived(b"/bin/kill\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_pkill_command(self) -> None:
        self.proto.lineReceived(b"/bin/pkill\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_killall_command(self) -> None:
        self.proto.lineReceived(b"/bin/killall\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_killall5_command(self) -> None:
        self.proto.lineReceived(b"/bin/killall5\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_su_command(self) -> None:
        self.proto.lineReceived(b"su\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_chown_command(self) -> None:
        self.proto.lineReceived(b"chown\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_chgrp_command(self) -> None:
        self.proto.lineReceived(b"chgrp\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_cd_output(self) -> None:
        path = "/usr/bin"

        self.proto.lineReceived(f"cd {path:s}".encode())
        self.assertEqual(self.tr.value(), PROMPT.replace(b"~", path.encode()))
        self.assertEqual(self.proto.cwd, path)

    def test_cd_error_output(self) -> None:
        self.proto.lineReceived(f"cd {NONEXISTEN_FILE:s}".encode())
        self.assertEqual(
            self.tr.value(),
            f"bash: cd: {NONEXISTEN_FILE:s}: No such file or directory\n".encode()
            + PROMPT,
        )


class ShellFileCommandsTests(unittest.TestCase):
    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")
    cpuinfo = proto.fs.file_contents("/proc/cpuinfo")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()

    def test_cat_output(self) -> None:
        self.proto.lineReceived(b"cat /proc/cpuinfo\n")
        self.assertEqual(self.tr.value(), self.cpuinfo + PROMPT)

    def test_grep_output(self) -> None:
        lines = [line.strip() for line in self.cpuinfo.splitlines() if b"cpu" in line]
        lines.append(b"")
        self.proto.lineReceived(b"grep cpu /proc/cpuinfo\n")
        self.assertEqual(self.tr.value(), b"\n".join(lines) + PROMPT)

    def test_tail_output(self) -> None:
        lines = [line.strip() for line in self.cpuinfo.splitlines()][-10:]
        lines.append(b"")
        self.proto.lineReceived(b"tail -n 10 /proc/cpuinfo\n")
        self.assertEqual(self.tr.value(), b"\n".join(lines) + PROMPT)

    def test_head_output(self) -> None:
        lines = [line.strip() for line in self.cpuinfo.splitlines()][:10]
        lines.append(b"")
        self.proto.lineReceived(b"head -n 10 /proc/cpuinfo\n")
        self.assertEqual(self.tr.value(), b"\n".join(lines) + PROMPT)

    def test_rm_output(self) -> None:
        self.proto.lineReceived(b"rm /usr/bin/gcc\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_rm_error_output(self) -> None:  # TODO: quotes?..
        self.proto.lineReceived(f"rm {NONEXISTEN_FILE:s}\n".encode())
        self.assertEqual(
            self.tr.value(),
            f"rm: cannot remove `{NONEXISTEN_FILE:s}': No such file or directory\n".encode()
            + PROMPT,
        )

    def test_cp_output(self) -> None:
        self.proto.lineReceived(b"cp /usr/bin/gcc /tmp\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_cp_error_output(self) -> None:  # TODO: quotes?..
        self.proto.lineReceived(f"cp {NONEXISTEN_FILE:s} /tmp\n".encode())
        self.assertEqual(
            self.tr.value(),
            f"cp: cannot stat `{NONEXISTEN_FILE:s}': No such file or directory\n".encode()
            + PROMPT,
        )

    def test_mv_output(self) -> None:
        self.proto.lineReceived(b"mv /usr/bin/awk /tmp\n")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_mv_error_output(self) -> None:  # TODO: quotes?..
        self.proto.lineReceived(f"mv {NONEXISTEN_FILE:s} /tmp\n".encode())
        self.assertEqual(
            self.tr.value(),
            f"mv: cannot stat `{NONEXISTEN_FILE:s}': No such file or directory\n".encode()
            + PROMPT,
        )

    def test_mkdir_output(self) -> None:
        path = "/tmp/hello"

        self.proto.lineReceived(f"mkdir {path:s}\n".encode())
        self.assertEqual(self.tr.value(), PROMPT)
        self.assertTrue(self.proto.fs.exists(path))
        self.assertTrue(self.proto.fs.isdir(path))

    def test_mkdir_error_output(self) -> None:  # TODO: quotes?..
        path = "/etc"

        self.proto.lineReceived(f"mkdir {path:s}\n".encode())
        self.assertEqual(
            self.tr.value(),
            f"mkdir: cannot create directory `{path:s}': File exists\n".encode()
            + PROMPT,
        )

    def test_rmdir_output(self) -> None:
        path = "/tmp/bye"

        self.proto.lineReceived(f"mkdir {path:s}\n".encode())
        self.tr.clear()
        self.proto.lineReceived(f"rmdir {path:s}\n".encode())
        self.assertEqual(self.tr.value(), PROMPT)
        self.assertFalse(self.proto.fs.exists(path))

    def test_rmdir_error_output(self) -> None:  # TODO: quotes?..
        self.proto.lineReceived(f"rmdir {NONEXISTEN_FILE:s}\n".encode())
        self.assertEqual(
            self.tr.value(),
            f"rmdir: failed to remove `{NONEXISTEN_FILE:s}': No such file or directory\n".encode()
            + PROMPT,
        )

    def test_pwd_output(self) -> None:
        self.proto.lineReceived(b"pwd\n")
        self.assertEqual(self.tr.value(), self.proto.cwd.encode() + b"\n" + PROMPT)

    def test_touch_output(self) -> None:
        path = "/tmp/test.txt"

        self.proto.lineReceived(f"touch {path:s}\n".encode())
        self.assertEqual(self.tr.value(), PROMPT)
        self.assertTrue(self.proto.fs.exists(path))


class ShellPipeCommandsTests(unittest.TestCase):
    proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
    tr = FakeTransport("", "31337")

    @classmethod
    def setUpClass(cls) -> None:
        cls.proto.makeConnection(cls.tr)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.proto.connectionLost()

    def setUp(self) -> None:
        self.tr.clear()

    def test_shell_pipe_with_cat_tail(self) -> None:
        self.proto.lineReceived(b"echo test | tail -n 1\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_shell_pipe_with_cat_head(self) -> None:
        self.proto.lineReceived(b"echo test | head -n 1\n")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    # def test_shell_busybox_with_cat_and_sudo_grep(self) -> None:
    #     self.proto.lineReceived(b'busybox cat /proc/cpuinfo | sudo grep cpu \n')
