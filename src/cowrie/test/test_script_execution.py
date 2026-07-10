# SPDX-FileCopyrightText: 2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for shell script execution via bash/sh and path-based invocation.
# ABOUTME: Covers shebang stripping, binary detection, comment stripping, and recursion depth limits.

from __future__ import annotations

import os
import unittest
from typing import ClassVar

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.shell.script import is_executable_binary
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

    def test_sh_rejects_binary_file(self) -> None:
        """sh <ELF binary> rejects it instead of splitting its bytes into
        commands and flooding the log (issue #40215)."""
        self.proto.lineReceived(
            b'printf "\\x7fELF\\x01\\x01\\x00\\nGARBAGE\\n" > /tmp/payload.x86'
        )
        self.tr.clear()
        self.proto.lineReceived(b"sh /tmp/payload.x86")
        output = self.tr.value()
        self.assertIn(b"cannot execute binary file", output)
        self.assertNotIn(b"GARBAGE", output)

    def test_bash_rejects_binary_file(self) -> None:
        self.proto.lineReceived(
            b'printf "\\x7fELF\\x01\\x01\\x00\\nGARBAGE\\n" > /tmp/payload2.x86'
        )
        self.tr.clear()
        self.proto.lineReceived(b"bash /tmp/payload2.x86")
        output = self.tr.value()
        self.assertIn(b"cannot execute binary file", output)
        self.assertNotIn(b"GARBAGE", output)

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
        self.proto.lineReceived(b'printf "#!/bin/sh\\necho absolute\\n" > /tmp/abs.sh')
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

    # -- multi-line flow control from a script file -------------------------

    def test_script_with_for_loop(self) -> None:
        """A for loop spanning multiple lines in a script file runs each pass."""
        self.proto.lineReceived(
            b"printf 'for i in 1 2 3\\ndo\\necho got $i\\ndone\\n' > /tmp/loop.sh"
        )
        self.tr.clear()
        self.proto.lineReceived(b"sh /tmp/loop.sh")
        self.assertEqual(self.tr.value(), b"got 1\ngot 2\ngot 3\n" + PROMPT)

    def test_script_with_if(self) -> None:
        """A multi-line if/else in a script file picks the right branch."""
        self.proto.lineReceived(
            b"printf 'if [ -f /etc/passwd ]\\nthen\\necho found\\n"
            b"else\\necho missing\\nfi\\n' > /tmp/cond.sh"
        )
        self.tr.clear()
        self.proto.lineReceived(b"bash /tmp/cond.sh")
        self.assertEqual(self.tr.value(), b"found\n" + PROMPT)

    def test_script_downloader_retry_idiom(self) -> None:
        """The try-each-mirror-until-one-works loop, run from a file."""
        self.proto.lineReceived(
            b"printf 'for u in a b c\\ndo\\necho fetch $u && break\\ndone\\n'"
            b" > /tmp/dl.sh"
        )
        self.tr.clear()
        self.proto.lineReceived(b"sh /tmp/dl.sh")
        self.assertEqual(self.tr.value(), b"fetch a\n" + PROMPT)

    def test_shebang_is_comment_not_executed(self) -> None:
        """The shebang line is treated as a comment and produces no output."""
        self.proto.lineReceived(
            b"printf '#!/bin/sh\\necho after_shebang\\n' > /tmp/sb.sh"
        )
        self.tr.clear()
        self.proto.lineReceived(b"sh /tmp/sb.sh")
        self.assertEqual(self.tr.value(), b"after_shebang\n" + PROMPT)

    def test_script_exit_status_propagates(self) -> None:
        """A script's exit status is the status of its last command."""
        self.proto.lineReceived(b"printf 'true\\nfalse\\n' > /tmp/st.sh")
        self.tr.clear()
        self.proto.lineReceived(b"sh /tmp/st.sh; echo rc=$?")
        self.assertEqual(self.tr.value(), b"rc=1\n" + PROMPT)


class BinaryDetectionTests(unittest.TestCase):
    """is_executable_binary distinguishes binaries from text scripts."""

    def test_elf_is_binary(self) -> None:
        self.assertTrue(is_executable_binary(b"\x7fELF\x02\x01\x01\x00rest"))

    def test_pe_is_binary(self) -> None:
        self.assertTrue(is_executable_binary(b"MZ\x90\x00\x03"))

    def test_nul_byte_is_binary(self) -> None:
        self.assertTrue(is_executable_binary(b"#!/bin/sh\nrun\x00me"))

    def test_plain_script_is_text(self) -> None:
        self.assertFalse(is_executable_binary(b"#!/bin/sh\necho hello\n"))

    def test_utf8_script_is_text(self) -> None:
        # Non-ASCII UTF-8 (a comment in another language) is still a script.
        self.assertFalse(is_executable_binary("# café\necho hi\n".encode()))

    def test_empty_is_not_binary(self) -> None:
        self.assertFalse(is_executable_binary(b""))

    def test_invalid_utf8_is_binary(self) -> None:
        self.assertTrue(is_executable_binary(b"\xff\xfe\x80\x81packed" * 50))

    def test_nul_past_sample_is_binary(self) -> None:
        # A self-extracting dropper: a large text header (no executable magic at
        # offset 0) with a binary blob appended past the inspection sample. The
        # NUL is what marks it binary, so the whole file must be scanned.
        contents = b"#!/bin/sh\n" + b"# padding\n" * 2000 + b"\x00\x01ELFblob"
        self.assertGreater(len(contents), 8192)
        self.assertTrue(is_executable_binary(contents))


class _AsyncCommand(HoneyPotCommand):
    """A command that pauses like wget/curl: start() launches and returns
    without exiting; the test fires completion by calling finish()."""

    pending: ClassVar[list[_AsyncCommand]] = []

    def start(self) -> None:
        _AsyncCommand.pending.append(self)

    def finish(self) -> None:
        self.exit()


class AsyncScriptExecutionTests(unittest.TestCase):
    """A script containing async commands (wget/curl) must run them one at a
    time and hand the prompt back when done (issue #40269)."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        _AsyncCommand.pending = []
        # Register the fake command in the shared class-level command table;
        # tearDown removes it again.
        self.proto.commands["asyncdl"] = _AsyncCommand
        self.tr.clear()

    def tearDown(self) -> None:
        del self.proto.commands["asyncdl"]
        self.proto.connectionLost()

    def test_sh_script_with_async_commands(self) -> None:
        self.proto.lineReceived(b"printf 'asyncdl\\nasyncdl\\n' > /tmp/a.sh")
        self.tr.clear()
        self.proto.lineReceived(b"sh /tmp/a.sh")

        # Sequential: only the first command has started; the second waits.
        self.assertEqual(len(_AsyncCommand.pending), 1)

        # Completing the first must not raise (the premature cmdstack.pop() left
        # it off the stack, so exit()'s remove() raised ValueError) and must
        # start the second.
        _AsyncCommand.pending[0].finish()
        self.assertEqual(len(_AsyncCommand.pending), 2)

        _AsyncCommand.pending[1].finish()

        # The script shell is gone and the interactive prompt is back, rather
        # than the session hanging on a stranded nested shell.
        self.assertEqual(len(self.proto.cmdstack), 1)
        self.assertTrue(self.proto.cmdstack[0].interactive)
        self.assertTrue(self.tr.value().endswith(PROMPT))

    def test_su_c_with_async_command(self) -> None:
        # su -c '<async>' takes the same nested-shell path as sh/bash.
        self.proto.lineReceived(b"su -c asyncdl")
        self.assertEqual(len(_AsyncCommand.pending), 1)
        _AsyncCommand.pending[0].finish()  # must not raise
        self.assertEqual(len(self.proto.cmdstack), 1)
        self.assertTrue(self.tr.value().endswith(PROMPT))
