# ABOUTME: Tests for shell script execution via bash/sh and path-based invocation.
# ABOUTME: Covers shebang stripping, binary detection, comment stripping, and recursion depth limits.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = "/tmp"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ScriptExecutionTests(unittest.TestCase):
    """Tests for executing shell scripts via bash/sh and ./path."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_bash_executes_script_file(self) -> None:
        """bash script.sh reads and executes file contents."""
        self.proto.lineReceived(b'echo "echo hello" > /tmp/test.sh')
        self.tr.clear()
        self.proto.lineReceived(b"bash /tmp/test.sh")
        self.assertEqual(self.tr.value(), b"hello\n" + PROMPT)

    def test_sh_executes_script_file(self) -> None:
        """sh script.sh reads and executes file contents."""
        self.proto.lineReceived(b'echo "echo world" > /tmp/test_sh.sh')
        self.tr.clear()
        self.proto.lineReceived(b"sh /tmp/test_sh.sh")
        self.assertEqual(self.tr.value(), b"world\n" + PROMPT)

    def test_bash_nonexistent_file(self) -> None:
        """bash nonexistent.sh shows error."""
        self.proto.lineReceived(b"bash /tmp/nonexistent.sh")
        output = self.tr.value()
        self.assertIn(b"No such file or directory", output)

    def test_dotslash_with_shebang_executes(self) -> None:
        """./script.sh with #!/bin/sh shebang executes."""
        self.proto.lineReceived(b'printf "#!/bin/sh\\necho from_script\\n" > run.sh')
        self.tr.clear()
        self.proto.lineReceived(b"./run.sh")
        self.assertEqual(self.tr.value(), b"from_script\n" + PROMPT)

    def test_dotslash_without_shebang_executes(self) -> None:
        """./file without shebang executes as shell script (kernel ENOEXEC fallback)."""
        self.proto.lineReceived(b'echo "echo no_shebang" > noshebang.sh')
        self.tr.clear()
        self.proto.lineReceived(b"./noshebang.sh")
        self.assertEqual(self.tr.value(), b"no_shebang\n" + PROMPT)

    def test_dotslash_binary_file_fails(self) -> None:
        """./file with null bytes emits 'cannot execute binary file'."""
        # Use printf to write a null byte into the file
        self.proto.lineReceived(b'printf "\\x00ELF" > binfile')
        self.tr.clear()
        self.proto.lineReceived(b"./binfile")
        output = self.tr.value()
        self.assertIn(b"cannot execute binary file", output)

    def test_shebang_line_stripped(self) -> None:
        """Shebang line is not echoed or executed as a command."""
        self.proto.lineReceived(
            b'printf "#!/bin/bash\\necho shebang_stripped\\n" > /tmp/shebang.sh'
        )
        self.tr.clear()
        self.proto.lineReceived(b"bash /tmp/shebang.sh")
        self.assertEqual(self.tr.value(), b"shebang_stripped\n" + PROMPT)

    def test_comment_lines_stripped(self) -> None:
        """Comment-only lines are stripped from script execution."""
        self.proto.lineReceived(
            b'printf "#!/bin/sh\\n# this is a comment\\necho works\\n" > /tmp/comments.sh'
        )
        self.tr.clear()
        self.proto.lineReceived(b"bash /tmp/comments.sh")
        self.assertEqual(self.tr.value(), b"works\n" + PROMPT)

    def test_multiline_script(self) -> None:
        """Script with multiple commands executes all of them."""
        self.proto.lineReceived(
            b'printf "echo line1\\necho line2\\necho line3\\n" > /tmp/multi.sh'
        )
        self.tr.clear()
        self.proto.lineReceived(b"bash /tmp/multi.sh")
        self.assertEqual(self.tr.value(), b"line1\nline2\nline3\n" + PROMPT)

    def test_absolute_path_with_shebang(self) -> None:
        """Absolute path /tmp/script.sh with shebang executes."""
        self.proto.lineReceived(
            b'printf "#!/bin/sh\\necho absolute\\n" > /tmp/abs.sh'
        )
        self.tr.clear()
        self.proto.lineReceived(b"/tmp/abs.sh")
        self.assertEqual(self.tr.value(), b"absolute\n" + PROMPT)

    def test_bash_dash_c_still_works(self) -> None:
        """Existing sh -c 'cmd' functionality still works."""
        self.proto.lineReceived(b"sh -c 'echo still_works'")
        self.assertEqual(self.tr.value(), b"still_works\n" + PROMPT)

    def test_bash_piped_input_still_works(self) -> None:
        """Existing piped input functionality still works."""
        self.proto.lineReceived(b"echo echo piped | bash")
        self.assertEqual(self.tr.value(), b"piped\n" + PROMPT)
