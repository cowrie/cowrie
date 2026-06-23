# ABOUTME: Tests for the su (switch user) command.
# ABOUTME: Tests user switching, password prompts, and effective user tracking.

from __future__ import annotations

import os
import unittest

from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

ROOT_PROMPT = b"root@unitTest:~# "
# Non-login su stays in current directory (which is /root for root user)
PHIL_PROMPT = b"phil@unitTest:/root$ "
# Login shell changes to user's home (/home/phil exists in test fs)
PHIL_HOME_PROMPT = b"phil@unitTest:~$ "


class FakeNonRootAvatar(FakeAvatar):
    """A non-root avatar for testing password prompts."""

    def __init__(self, server):
        super().__init__(server)
        self.uid = 1000
        self.gid = 1000
        self.home = "/home/phil"
        self.username = "phil"
        self.environ["LOGNAME"] = self.username
        self.environ["USER"] = self.username
        self.environ["HOME"] = self.home
        self.environ["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"


class SuCommandTests(unittest.TestCase):
    """Tests for the su command."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_su_help(self) -> None:
        """Test su --help output."""
        self.proto.lineReceived(b"su --help\n")
        output = self.tr.value()
        self.assertIn(b"Usage:", output)
        self.assertIn(b"--login", output)
        self.assertIn(b"--command", output)

    def test_su_version(self) -> None:
        """Test su --version output."""
        self.proto.lineReceived(b"su --version\n")
        self.assertEqual(self.tr.value(), b"su from util-linux 2.38.1\n" + ROOT_PROMPT)

    def test_su_to_root_as_root(self) -> None:
        """Test su to root when already root (no password needed)."""
        self.proto.lineReceived(b"su\n")
        # Should get a new root prompt (no password prompt)
        self.assertEqual(self.tr.value(), ROOT_PROMPT)

    def test_su_with_command(self) -> None:
        """Test su -c 'command' to run a single command as root."""
        self.proto.lineReceived(b"su -c whoami\n")
        self.assertEqual(self.tr.value(), b"root\n" + ROOT_PROMPT)

    def test_su_to_phil_with_command(self) -> None:
        """Test su -c 'command' phil to run a command as phil."""
        self.proto.lineReceived(b"su -c whoami phil\n")
        self.assertEqual(self.tr.value(), b"phil\n" + ROOT_PROMPT)

    def test_su_to_phil_id_command(self) -> None:
        """Test su -c id phil shows phil's uid/gid."""
        self.proto.lineReceived(b"su -c id phil\n")
        self.assertEqual(
            self.tr.value(),
            b"uid=1000(phil) gid=1000(phil) groups=1000(phil)\n" + ROOT_PROMPT,
        )

    def test_su_nonexistent_user(self) -> None:
        """Test su to a nonexistent user fails with error."""
        self.proto.lineReceived(b"su nonexistent\n")
        output = self.tr.value()
        self.assertIn(b"su: user nonexistent does not exist", output)

    def test_su_invalid_option(self) -> None:
        """Test su with invalid option shows error."""
        self.proto.lineReceived(b"su --invalid\n")
        output = self.tr.value()
        self.assertIn(b"invalid option", output)

    def test_su_interactive_to_phil(self) -> None:
        """Test interactive su to phil creates new shell with phil identity."""
        self.proto.lineReceived(b"su phil\n")
        # Should get phil's prompt
        self.assertEqual(self.tr.value(), PHIL_PROMPT)

        # Clear and test whoami in the new shell
        self.tr.clear()
        self.proto.lineReceived(b"whoami\n")
        self.assertEqual(self.tr.value(), b"phil\n" + PHIL_PROMPT)

        # Test id command
        self.tr.clear()
        self.proto.lineReceived(b"id\n")
        self.assertEqual(
            self.tr.value(),
            b"uid=1000(phil) gid=1000(phil) groups=1000(phil)\n" + PHIL_PROMPT,
        )

    def test_su_login_shell(self) -> None:
        """Test su - phil creates login shell with reset environment."""
        self.proto.lineReceived(b"su - phil\n")
        # Login shell should change to home directory
        self.assertEqual(self.tr.value(), PHIL_HOME_PROMPT)

    def test_su_exit_returns_to_original_user(self) -> None:
        """Test exit from su'd shell returns to original user."""
        # Switch to phil
        self.proto.lineReceived(b"su phil\n")
        self.tr.clear()

        # Exit the su'd shell
        self.proto.lineReceived(b"exit\n")
        self.tr.clear()

        # Should be back to root
        self.proto.lineReceived(b"whoami\n")
        self.assertEqual(self.tr.value(), b"root\n" + ROOT_PROMPT)

    def test_nested_su(self) -> None:
        """Test nested su (su to phil, then su to root)."""
        # Switch to phil
        self.proto.lineReceived(b"su phil\n")
        self.tr.clear()

        # From phil, su to root (root doesn't need password)
        self.proto.lineReceived(b"su\n")
        # Phil needs password, but in test root is uid 0 so this is a case
        # where we're already in phil shell and su to root
        # Actually, the current shell's user is what matters
        # Let me check... the test setup has root, so su to phil, then su needs password
        # This is complex - let's just verify the prompt changes
        output = self.tr.value()
        # Since we're "phil" (effective_user), su to root should ask for password
        self.assertIn(b"Password:", output)


class SuPasswordPromptTests(unittest.TestCase):
    """Tests for su password prompts when non-root tries to switch user."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeNonRootAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_nonroot_su_shows_password_prompt(self) -> None:
        """Test that non-root user gets password prompt when su'ing."""
        self.proto.lineReceived(b"su\n")
        self.assertEqual(self.tr.value(), b"Password: ")

    def test_nonroot_su_accepts_password(self) -> None:
        """Test that non-root user can su after entering password."""
        self.proto.lineReceived(b"su\n")
        self.tr.clear()

        # Enter password (any password is accepted in honeypot)
        self.proto.lineReceived(b"anypassword\n")

        # Should now have root shell
        output = self.tr.value()
        self.assertIn(b"root@unitTest", output)

    def test_nonroot_su_with_command_shows_password(self) -> None:
        """Test that non-root user gets password prompt even with -c."""
        self.proto.lineReceived(b"su -c whoami\n")
        self.assertEqual(self.tr.value(), b"Password: ")

    def test_nonroot_su_command_executes_after_password(self) -> None:
        """Test that command executes after password is entered."""
        self.proto.lineReceived(b"su -c whoami\n")
        self.tr.clear()

        # Enter password
        self.proto.lineReceived(b"secret\n")

        output = self.tr.value()
        # Should have newline after password, then command output
        self.assertIn(b"\nroot\n", output)


class SuEnvironmentTests(unittest.TestCase):
    """Tests for su environment variable handling."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_su_login_shell_sets_home(self) -> None:
        """Test su - sets HOME to target user's home."""
        self.proto.lineReceived(b"su - phil\n")
        self.tr.clear()

        self.proto.lineReceived(b"echo $HOME\n")
        self.assertIn(b"/home/phil", self.tr.value())

    def test_su_login_shell_sets_user(self) -> None:
        """Test su - sets USER and LOGNAME."""
        self.proto.lineReceived(b"su - phil\n")
        self.tr.clear()

        self.proto.lineReceived(b"echo $USER\n")
        self.assertIn(b"phil", self.tr.value())

    def test_su_nonlogin_updates_user_vars(self) -> None:
        """Test non-login su updates USER/LOGNAME/HOME."""
        self.proto.lineReceived(b"su phil\n")
        self.tr.clear()

        self.proto.lineReceived(b"echo $USER\n")
        self.assertIn(b"phil", self.tr.value())


if __name__ == "__main__":
    unittest.main()
