# See the COPYRIGHT file for more information
from __future__ import annotations

from typing import Any

from cowrie.shell.command import HoneyPotCommand

commands: dict[str, Any] = {}


class Command_chpasswd(HoneyPotCommand):
    """
    chpasswd command simulation
    """

    input_data: bytes = b""

    def call(self) -> None:
        if not self.input_data:
            return

        lines = self.input_data.split(b"\n")
        c = 0

        for line in lines:
            c += 1
            line = line.strip()

            if not line:
                continue

            parts = line.split(b":")

            if len(parts) != 2:
                self.write(
                    f"chpasswd: line {c}: missing new password\n"
                )
                continue

            username = parts[0].strip()
            password = parts[1].strip()

            if not username:
                self.write(
                    f"chpasswd: line {c}: missing username\n"
                )
                continue

            if not password:
                self.write(
                    f"chpasswd: line {c}: missing new password\n"
                )
                continue

    def start(self) -> None:
        self.input_data = b""

    def lineReceived(self, line: bytes) -> None:
        self.input_data += line + b"\n"

    def eofReceived(self) -> None:
        self.call()
        self.exit()


commands["/usr/sbin/chpasswd"] = Command_chpasswd
commands["chpasswd"] = Command_chpasswd
