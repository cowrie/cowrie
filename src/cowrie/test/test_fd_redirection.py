# Copyright (c) 2025 @CoreZen
# See LICENSE for details.
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


class ShellFdRedirectionTests(unittest.TestCase):
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

    def test_redirect_stderr_to_devnull(self) -> None:
        self.proto.lineReceived(b"cat /proc/uptime 2>/dev/null")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_redirect_stderr_into_pipe(self) -> None:
        self.proto.lineReceived(b"cat missingfile 2>&1 | grep 'No such file'")
        self.assertEqual(
            self.tr.value(),
            b"cat: missingfile: No such file or directory\n" + PROMPT,
        )

    def test_redirect_stderr_to_file(self) -> None:
        self.proto.lineReceived(b"cat missingfile 2> errfile; cat errfile")
        self.assertEqual(
            self.tr.value(),
            b"cat: missingfile: No such file or directory\n" + PROMPT,
        )

    def test_redirect_stdout_and_append(self) -> None:
        self.proto.lineReceived(
            b"echo first > outredir; echo second >> outredir; cat outredir"
        )
        self.assertEqual(self.tr.value(), b"first\nsecond\n" + PROMPT)

    def test_redirect_stdout_and_stderr_to_file(self) -> None:
        self.proto.lineReceived(b"cat missingfile 2>&1 > combined; cat combined")
        self.assertEqual(
            self.tr.value(),
            b"cat: missingfile: No such file or directory\n" + PROMPT,
        )

    def test_stdout_overwrite(self) -> None:
        self.proto.lineReceived(b"echo hi > outoverwrite; echo bye > outoverwrite; cat outoverwrite")
        self.assertEqual(self.tr.value(), b"bye\n" + PROMPT)

    def test_stdout_overwrite_and_stderr_pipe(self) -> None:
        self.proto.lineReceived(b"cat missingfile 2>&1 1> outonly; cat outonly")
        # stderr should still reach the pipe (2>&1 happens before stdout redirection)
        self.assertEqual(
            self.tr.value(),
            b"cat: missingfile: No such file or directory\n" + PROMPT,
        )

    def test_stdin_redirection(self) -> None:
        self.proto.lineReceived(b"cat < /etc/passwd")
        # Default honeyfs passwd has root line starting with root:x:
        output = self.tr.value()
        self.assertTrue(output.startswith(b"root:x:"), output)
        self.assertTrue(output.endswith(PROMPT))

    def test_separate_stdout_stderr_files(self) -> None:
        self.proto.lineReceived(
            b"cat missingfile > out_file 2> err_file; cat out_file; cat err_file"
        )
        self.assertEqual(
            self.tr.value(),
            b"cat: missingfile: No such file or directory\n" + PROMPT,
        )

    def test_fd_dup_chain(self) -> None:
        self.proto.lineReceived(b"cat missingfile 3>&1 1>&2 2> chained; cat chained")
        self.assertEqual(
            self.tr.value(),
            b"cat: missingfile: No such file or directory\n" + PROMPT,
        )

    def test_unknown_command_redirect(self) -> None:
        self.proto.lineReceived(b"unknowncommand 2> err_unknown; cat err_unknown")
        self.assertIn(b"command not found", self.tr.value())
        self.assertTrue(self.tr.value().endswith(PROMPT))

    def test_stdin_redirection_with_pipe(self) -> None:
        self.proto.lineReceived(b"< /etc/hosts cat | cat")
        output = self.tr.value()
        self.assertTrue(output.endswith(PROMPT))
        # Should contain at least one line from hosts file if present
        self.assertIn(b"localhost", output)

    def test_append_preserves_existing(self) -> None:
        self.proto.lineReceived(b"echo first > appendfile; echo second >> appendfile; echo third >> appendfile; cat appendfile")
        self.assertEqual(
            self.tr.value(),
            b"first\nsecond\nthird\n" + PROMPT,
        )

    def test_invalid_fd_redirection(self) -> None:
        self.proto.lineReceived(b"echo test 5> outfile")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_multiple_output_redirections(self) -> None:
        # Last one should win
        self.proto.lineReceived(b"echo test > file1 > file2; cat file1; echo separator; cat file2")
        # file1 should be empty (created but not written to?), file2 has content
        # In bash: file1 is empty, file2 has "test"
        self.assertEqual(
            self.tr.value(),
            b"separator\ntest\n" + PROMPT,
        )

    def test_redirection_without_command(self) -> None:
        # > file should create empty file
        self.proto.lineReceived(b"> emptyfile; cat emptyfile")
        self.assertEqual(self.tr.value(), PROMPT)
        # Verify file exists (cat didn't error)

    def test_input_from_missing_file(self) -> None:
        self.proto.lineReceived(b"cat < non_existent_file")
        self.assertIn(b"No such file or directory", self.tr.value())
        self.assertTrue(self.tr.value().endswith(PROMPT))

    def test_swap_stdout_stderr(self) -> None:
        # 3>&1 1>&2 2>&3
        # This swaps stdout and stderr.
        
        cmd = b"cat missingfile > out_file 2> err_file 3>&1 1>&2 2>&3; cat out_file; echo SEP; cat err_file"
        self.proto.lineReceived(cmd)
        output = self.tr.value()
        
        # Expected:
        # out_file contains "cat: missingfile: No such file or directory\n"
        # err_file is empty
        # Output should be: cat: missingfile: ...\nSEP\n
        
        self.assertIn(b"cat: missingfile: No such file or directory\nSEP\n", output)
        self.assertTrue(output.endswith(PROMPT))

    def test_filename_with_spaces(self) -> None:
        self.proto.lineReceived(b"echo test > 'file with spaces'; cat 'file with spaces'")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_multiple_redirections_same_file(self) -> None:
        self.proto.lineReceived(b"echo test > file > file; cat file")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)

    def test_input_output_same_file(self) -> None:
        # In a real shell, `cat < file > file` truncates the file before reading, resulting in empty file.
        # Cowrie should emulate this behavior.
        self.proto.lineReceived(b"echo content > file; cat < file > file; cat file")
        self.assertEqual(self.tr.value(), PROMPT)

    def test_stdout_to_stderr_to_file(self) -> None:
        self.proto.lineReceived(b"echo test 1>&2 2> file; cat file")
        self.assertEqual(self.tr.value(), b"test\n" + PROMPT)
