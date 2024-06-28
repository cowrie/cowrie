# Copyright (c) 2018 Michel Oosterhof
# See LICENSE for details.
from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "share/cowrie/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ShellLsCommandTests(unittest.TestCase):
    """Test for cowrie/commands/ls.py."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost("tearDown From Unit Test")

    def test_ls_command_001(self) -> None:
        self.proto.lineReceived(b"ls NonExisting\n")
        self.assertEqual(
            self.tr.value(),
            b"ls: cannot access /root/NonExisting: No such file or directory\n"
            + PROMPT,
        )

    def test_ls_command_002(self) -> None:
        self.proto.lineReceived(b"ls /\n")
        self.assertEqual(
            self.tr.value(),
            b"bin        boot       dev        etc        home       initrd.img lib        \nlost+found media      mnt        opt        proc       root       run        \nsbin       selinux    srv        sys        test2      tmp        usr        \nvar        vmlinuz    \n"
            + PROMPT,
        )

    def test_ls_command_003(self) -> None:
        self.proto.lineReceived(b"ls -l /\n")
        self.assertEqual(
            self.tr.value(),
            b"drwxr-xr-x 1 root root  4096 2013-04-05 17:23 bin\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:32 boot\ndrwxr-xr-x 1 root root  3060 2013-04-05 17:33 dev\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:36 etc\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:32 home\nlrwxrwxrwx 1 root root    32 2013-04-05 17:23 initrd.img -> /boot/initrd.img-3.2.0-4-686-pae\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:31 lib\ndrwx------ 1 root root 16384 2013-04-05 17:22 lost+found\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:22 media\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:22 mnt\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:22 opt\ndr-xr-xr-x 1 root root     0 2013-04-05 17:33 proc\ndrwx------ 1 root root  4096 2013-04-05 17:55 root\ndrwxr-xr-x 1 root root   380 2013-04-05 17:36 run\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:33 sbin\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:22 selinux\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:22 srv\ndrwxr-xr-x 1 root root     0 2013-04-05 17:33 sys\n-rwxr-xr-x 1 root root   500 2021-05-30 10:14 test2\ndrwxrwxrwt 1 root root  4096 2013-04-05 17:47 tmp\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:22 usr\ndrwxr-xr-x 1 root root  4096 2013-04-05 17:22 var\nlrwxrwxrwx 1 root root    28 2013-04-05 17:23 vmlinuz -> /boot/vmlinuz-3.2.0-4-686-pae\n"
            + PROMPT,
        )

    def test_ls_command_004(self) -> None:
        self.proto.lineReceived(b"ls -lh /\n")
        print(self.tr.value())
        self.assertEqual(
            self.tr.value(),
            b"drwxr-xr-x 1 root root  4.0K 2013-04-05 17:23 bin\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:32 boot\ndrwxr-xr-x 1 root root  3.0K 2013-04-05 17:33 dev\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:36 etc\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:32 home\nlrwxrwxrwx 1 root root    32 2013-04-05 17:23 initrd.img -> /boot/initrd.img-3.2.0-4-686-pae\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:31 lib\ndrwx------ 1 root root 16.0K 2013-04-05 17:22 lost+found\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:22 media\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:22 mnt\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:22 opt\ndr-xr-xr-x 1 root root     0 2013-04-05 17:33 proc\ndrwx------ 1 root root  4.0K 2013-04-05 17:55 root\ndrwxr-xr-x 1 root root   380 2013-04-05 17:36 run\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:33 sbin\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:22 selinux\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:22 srv\ndrwxr-xr-x 1 root root     0 2013-04-05 17:33 sys\n-rwxr-xr-x 1 root root   500 2021-05-30 10:14 test2\ndrwxrwxrwt 1 root root  4.0K 2013-04-05 17:47 tmp\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:22 usr\ndrwxr-xr-x 1 root root  4.0K 2013-04-05 17:22 var\nlrwxrwxrwx 1 root root    28 2013-04-05 17:23 vmlinuz -> /boot/vmlinuz-3.2.0-4-686-pae\n"
            + PROMPT,
        )
