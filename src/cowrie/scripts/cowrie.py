#!/usr/bin/env python

# SPDX-FileCopyrightText: 2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Cowrie service management script.

This script provides functionality to start, stop, restart, and check the status
of the Cowrie honeypot service using the Twisted application framework.
"""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import NoReturn

from cowrie.core.resources import read_data_bytes


def get_pid_file() -> Path:
    """Get the path to the PID file (cwd-relative)."""
    return Path("var/run/cowrie.pid")


def check_initialized() -> None:
    """Refuse to start unless cwd looks like a cowrie state directory or a
    cowrie source checkout. Marker files (any one of):

      - ./etc/cowrie.cfg           operator config
      - ./etc/cowrie.cfg.dist      operator-extracted defaults template
      - ./src/cowrie/data/etc/cowrie.cfg.dist  source-checkout repo root
    """
    markers = (
        Path("etc/cowrie.cfg"),
        Path("etc/cowrie.cfg.dist"),
        Path("src/cowrie/data/etc/cowrie.cfg.dist"),
    )
    if any(m.is_file() for m in markers):
        return
    print(
        "ERROR: cowrie is not initialised in this directory.\n"
        "  Expected one of:\n"
        "    ./etc/cowrie.cfg\n"
        "    ./etc/cowrie.cfg.dist\n"
        "    ./src/cowrie/data/etc/cowrie.cfg.dist  (source checkout)\n"
        "  cd into your cowrie state directory before starting."
    )
    sys.exit(1)


def read_pid() -> int | None:
    """Read the PID from the PID file, return None if not found or invalid."""
    pid_file = get_pid_file()
    try:
        with pid_file.open() as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def is_process_running(pid: int) -> bool:
    """Check if a process with the given PID is running."""
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def remove_stale_pidfile() -> None:
    """Remove the PID file if it exists."""
    pid_file = get_pid_file()
    if pid_file.exists():
        pid_file.unlink()
        print(f"Removed stale PID file {pid_file}")


def cowrie_status() -> None:
    """Print the current status of Cowrie."""
    pid = read_pid()
    if pid is None:
        print("cowrie is not running.")
        return

    if is_process_running(pid):
        print(f"cowrie is running (PID: {pid}).")
    else:
        print(f"cowrie is not running (PID: {pid}).")
        remove_stale_pidfile()


def first_time_use() -> None:
    """Display first-time use message (cwd-relative log path)."""
    if not Path("var/log/cowrie/cowrie.log").exists():
        print()
        print("Join the Cowrie community at: https://www.cowrie.org/slack/")
        print()


def python_version_warning() -> None:
    """Display Python version warnings if needed."""
    version_info = sys.version_info

    if version_info < (3, 10):
        print()
        print("DEPRECATION: Python<3.10 is no longer supported by Cowrie.")
        print()


def check_root() -> None:
    """Check if running as root and exit if so."""
    if os.name == "posix" and os.getuid() == 0:
        print("ERROR: You must not run cowrie as root!")
        sys.exit(1)


def cowrie_start(args: list[str]) -> NoReturn:
    """Start the Cowrie service."""
    check_initialized()
    first_time_use()
    python_version_warning()

    # Check if already running
    pid = read_pid()
    if pid is not None and is_process_running(pid):
        print(f"cowrie is already running (PID: {pid}).")
        sys.exit(1)

    # Remove stale PID file if it exists
    if pid is not None:
        remove_stale_pidfile()

    # Build twistd arguments
    twisted_args = ["twistd", "--umask=0022"]

    # Add PID file unless running in foreground
    stdout_mode = os.environ.get("COWRIE_STDOUT", "").lower() == "yes"
    if not stdout_mode:
        pid_file = get_pid_file()
        # Ensure PID file directory exists
        pid_file.parent.mkdir(parents=True, exist_ok=True)
        twisted_args.extend(["--pidfile", str(pid_file)])
        twisted_args.extend(["--logger", "cowrie.python.logfile.logger"])
    else:
        twisted_args.extend(["-n", "-l", "-"])

    # Add any additional arguments passed to the script
    twisted_args.extend(args)

    # Add the cowrie plugin
    twisted_args.append("cowrie")

    print(f"Starting cowrie: [{' '.join(twisted_args)}]...")

    # Check for authbind
    authfile = Path("/etc/authbind/byport/22")
    authbind_enabled = (
        os.environ.get("AUTHBIND_ENABLED", "").lower() != "no"
        and authfile.exists()
        and os.access(authfile, os.X_OK)
        and subprocess.run(["which", "authbind"], capture_output=True).returncode == 0
    )

    if authbind_enabled:
        twisted_args.insert(0, "--deep")
        twisted_args.insert(0, "authbind")

    # Execute twistd
    os.execvp(twisted_args[0], twisted_args)


def cowrie_stop() -> None:
    """Stop the Cowrie service."""
    pid = read_pid()
    if pid is None:
        print("cowrie is not running.")
        return

    if not is_process_running(pid):
        print("cowrie is not running.")
        remove_stale_pidfile()
        return

    print("Stopping cowrie...")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print("cowrie is not running.")
        remove_stale_pidfile()


def cowrie_force_stop() -> None:
    """Force stop the Cowrie service."""
    pid = read_pid()
    if pid is None:
        print("cowrie is not running.")
        return

    if not is_process_running(pid):
        print("cowrie is not running.")
        remove_stale_pidfile()
        return

    print("Stopping cowrie...", end="", flush=True)
    try:
        os.kill(pid, signal.SIGTERM)

        # Wait up to 60 seconds for graceful shutdown
        for _ in range(60):
            time.sleep(1)
            print(".", end="", flush=True)
            if not is_process_running(pid):
                print("terminated.")
                return

        # Force kill if still running
        os.kill(pid, signal.SIGKILL)
        print("killed.")
    except ProcessLookupError:
        print("\ncowrie is not running.")
        remove_stale_pidfile()


def cowrie_restart(args: list[str]) -> NoReturn:
    """Restart the Cowrie service."""
    cowrie_stop()
    time.sleep(2)  # Brief pause to ensure clean shutdown
    cowrie_start(args)


def cowrie_shell() -> NoReturn:
    """Launch a shell (mainly for Docker use)."""
    shell = os.environ.get("SHELL", "/bin/bash")
    os.execvp(shell, [shell])


def cowrie_init() -> None:
    """Set up the current directory as a cowrie state directory.

    Writes ./etc/cowrie.cfg from the bundled template and creates the
    var/ skeleton (log/cowrie, lib/cowrie, run) so the first
    `cowrie start` does not trip on missing parent directories.

    Intended for fresh state directories (pip-install Mode A): the user
    cd's into the directory they want cowrie to run in, runs `cowrie
    init` once, edits the config to taste, then `cowrie start`.

    Refuses to overwrite an existing ./etc/cowrie.cfg.
    """
    target = Path("etc/cowrie.cfg")
    if target.exists():
        print(f"ERROR: {target} already exists; refusing to overwrite.")
        sys.exit(1)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(read_data_bytes("etc", "cowrie.cfg.dist"))
    print(f"Wrote {target}")

    state_dirs = (
        "var/log/cowrie",
        "var/lib/cowrie",
        "var/lib/cowrie/downloads",
        "var/lib/cowrie/tty",
        "var/run",
    )
    for sub in state_dirs:
        Path(sub).mkdir(parents=True, exist_ok=True)
    print(f"Created {', '.join(state_dirs)}")

    print(
        "Edit etc/cowrie.cfg to customise hostname, ports, etc., then run `cowrie start`."
    )


def main() -> NoReturn:
    """Main entry point for the cowrie management script."""
    check_root()
    parser = argparse.ArgumentParser(description="Cowrie honeypot service manager")
    parser.add_argument(
        "command",
        choices=[
            "init",
            "start",
            "stop",
            "force-stop",
            "restart",
            "status",
            "shell",
            "bash",
            "sh",
        ],
        help="Command to execute",
    )
    parser.add_argument(
        "args", nargs="*", help="Additional arguments to pass to twistd"
    )

    parsed_args = parser.parse_args()

    if parsed_args.command == "init":
        cowrie_init()
        sys.exit(0)
    elif parsed_args.command == "start":
        cowrie_start(parsed_args.args)
    elif parsed_args.command == "stop":
        cowrie_stop()
        sys.exit(0)
    elif parsed_args.command == "force-stop":
        cowrie_force_stop()
        sys.exit(0)
    elif parsed_args.command == "restart":
        cowrie_restart(parsed_args.args)
    elif parsed_args.command == "status":
        cowrie_status()
        sys.exit(0)
    elif parsed_args.command in ("shell", "bash", "sh"):
        cowrie_shell()
    else:
        parser.print_help()
        sys.exit(1)


def run() -> NoReturn:
    """Entry point function for setuptools console script."""
    main()


if __name__ == "__main__":
    main()
