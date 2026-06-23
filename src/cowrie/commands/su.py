# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Implements the su (switch user) command for the honeypot.
# ABOUTME: Allows switching to another user identity with password prompting.

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cowrie.shell import pwd
from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.honeypot import HoneyPotShell

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}

SU_HELP = """Usage:
 su [options] [-] [<user> [<argument>...]]

Change the effective user ID and group ID to that of <user>.
A mere - implies -l.  If <user> is not given, root is assumed.

Options:
 -m, -p, --preserve-environment      do not reset environment variables
 -w, --whitelist-environment <list>  don't reset specified variables

 -g, --group <group>             specify the primary group
 -G, --supp-group <group>        specify a supplemental group

 -, -l, --login                  make the shell a login shell
 -c, --command <command>         pass a single command to the shell with -c
 --session-command <command>     pass a single command to the shell with -c
                                   and do not create a new session
 -f, --fast                      pass -f to the shell (for csh or tcsh)
 -s, --shell <shell>             run <shell> if /etc/shells allows it
 -P, --pty                       create a new pseudo-terminal

 -h, --help                      display this help
 -V, --version                   display version

For more details see su(1).
"""


class Command_su(HoneyPotCommand):
    """
    su command - switch user identity
    """

    _su_state: dict[str, Any]

    def start(self) -> None:
        login_shell = False
        preserve_env = False
        target_user = "root"
        command: str | None = None

        # Parse arguments
        i = 0
        while i < len(self.args):
            arg = self.args[i]
            if arg == "-" or arg == "-l" or arg == "--login":
                login_shell = True
            elif arg in ("-m", "-p", "--preserve-environment"):
                preserve_env = True
            elif arg in ("-c", "--command"):
                i += 1
                if i < len(self.args):
                    command = self.args[i]
            elif arg in ("-h", "--help"):
                self.write(SU_HELP)
                self.exit()
                return
            elif arg in ("-V", "--version"):
                self.write("su from util-linux 2.38.1\n")
                self.exit()
                return
            elif arg in ("-s", "--shell", "-g", "--group", "-G", "--supp-group"):
                # These take an argument, skip it
                i += 1
            elif arg in ("-f", "--fast", "-P", "--pty"):
                # Flags we accept but ignore
                pass
            elif arg.startswith("-"):
                self.errorWrite(f"su: invalid option -- '{arg[1:]}'\n")
                self.errorWrite("Try 'su --help' for more information.\n")
                self.exit()
                return
            else:
                # Non-option argument is the target user
                target_user = arg
            i += 1

        # Look up target user in passwd
        try:
            pwentry = pwd.Passwd().getpwnam(target_user)
        except KeyError:
            self.errorWrite(
                f"su: user {target_user} does not exist or the user entry does not contain all the required fields\n"
            )
            self.exit()
            return

        # Store state for after password entry
        self._su_state = {
            "pwentry": pwentry,
            "login_shell": login_shell,
            "preserve_env": preserve_env,
            "command": command,
        }

        # Root doesn't need to enter a password (check effective uid, not session uid)
        if self.current_user["uid"] == 0:
            self.switch_user()
        else:
            # Prompt for password (hidden input)
            self.protocol.password_input = True
            self.write("Password: ")

    def lineReceived(self, line: str) -> None:
        """Handle password input - honeypot accepts any password."""
        self.protocol.password_input = False
        self.protocol.terminal.write(b"\n")
        self.switch_user()

    def switch_user(self) -> None:
        """Switch to the target user and start a new shell."""
        state = self._su_state
        pwentry = state["pwentry"]
        login_shell = state["login_shell"]
        preserve_env = state["preserve_env"]
        command = state["command"]

        effective_user = {
            "uid": pwentry["pw_uid"],
            "gid": pwentry["pw_gid"],
            "username": pwentry["pw_name"],
            "home": pwentry["pw_dir"],
            "shell": pwentry.get("pw_shell", "/bin/bash"),
        }

        if command:
            self.execute_command_as_user(command, effective_user, preserve_env)
        else:
            self.interactive_shell_as_user(effective_user, login_shell, preserve_env)

    def execute_command_as_user(
        self, command: str, effective_user: dict[str, Any], preserve_env: bool
    ) -> None:
        """Execute a single command as the target user."""
        # Create a non-interactive shell to run the command
        shell = HoneyPotShell(
            self.protocol, interactive=False, effective_user=effective_user
        )

        # Update environment for the target user
        if not preserve_env:
            shell.environ["USER"] = effective_user["username"]
            shell.environ["LOGNAME"] = effective_user["username"]
            shell.environ["HOME"] = effective_user["home"]

        self.protocol.cmdstack.append(shell)
        shell.lineReceived(command)
        self.protocol.cmdstack.pop()
        self.exit()

    def interactive_shell_as_user(
        self, effective_user: dict[str, Any], login_shell: bool, preserve_env: bool
    ) -> None:
        """Start an interactive shell as the target user."""
        # For login shell, change cwd BEFORE creating shell (since shell shows prompt)
        if login_shell:
            if self.protocol.fs.exists(effective_user["home"]):
                self.protocol.cwd = effective_user["home"]
            else:
                self.protocol.cwd = "/"

        shell = HoneyPotShell(
            self.protocol, interactive=True, effective_user=effective_user
        )

        if login_shell:
            # Login shell: reset environment to target user's defaults
            shell.environ = {
                "HOME": effective_user["home"],
                "USER": effective_user["username"],
                "LOGNAME": effective_user["username"],
                "SHELL": effective_user.get("shell", "/bin/bash"),
                "SHLVL": "1",
                "TERM": self.environ.get("TERM", "xterm"),
            }
            if effective_user["uid"] == 0:
                shell.environ["PATH"] = (
                    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                )
            else:
                shell.environ["PATH"] = (
                    "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
                )
        elif not preserve_env:
            # Non-login, non-preserve: update user-specific vars only
            shell.environ["USER"] = effective_user["username"]
            shell.environ["LOGNAME"] = effective_user["username"]
            shell.environ["HOME"] = effective_user["home"]
        # If preserve_env is True, keep existing environ (already copied)

        self.protocol.cmdstack.append(shell)
        self.protocol.cmdstack.remove(self)
        shell.showPrompt()


commands["su"] = Command_su
commands["/bin/su"] = Command_su
commands["/usr/bin/su"] = Command_su
