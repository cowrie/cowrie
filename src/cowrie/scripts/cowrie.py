#!/usr/bin/env python

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


def find_cowrie_directory() -> Path:
    """Determine the Cowrie directory based on the script location."""
    script_path = Path(__file__).resolve()
    # Go up from scripts/cowrie.py to src/cowrie to root
    return script_path.parent.parent.parent.parent


def get_pid_file() -> Path:
    """Get the path to the PID file."""
    cowrie_dir = find_cowrie_directory()
    return cowrie_dir / "var" / "run" / "cowrie.pid"


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


def setup_environment() -> None:
    """Set up the environment for running Cowrie."""
    cowrie_dir = find_cowrie_directory()
    os.chdir(cowrie_dir)


def first_time_use() -> None:
    """Display first-time use message."""
    cowrie_dir = find_cowrie_directory()
    log_file = cowrie_dir / "var" / "log" / "cowrie" / "cowrie.log"

    if not log_file.exists():
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
    setup_environment()
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


def main() -> NoReturn:
    """Main entry point for the cowrie management script."""
    check_root()
    parser = argparse.ArgumentParser(description="Cowrie honeypot service manager")
    parser.add_argument(
        "command",
        choices=[
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

    if parsed_args.command == "start":
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
