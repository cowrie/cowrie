# SPDX-FileCopyrightText: 2009-2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from cowrie.shell.command import HoneyPotCommand

if TYPE_CHECKING:
    from collections.abc import Callable

commands: dict[str, Callable] = {}


class Command_ps(HoneyPotCommand):
    def columns(self) -> int:
        """Width to truncate each line to. COLUMNS is an ordinary shell
        variable that export sets to anything at all, so fall back to the
        default width rather than trusting it to be a number."""
        try:
            return int(self.environ["COLUMNS"])
        except (KeyError, ValueError):
            return 80

    def call(self) -> None:
        user = str(self.user["username"])
        args = ""
        if self.args:
            args = self.args[0].strip()
        (
            _user,
            _pid,
            _cpu,
            _mem,
            _vsz,
            _rss,
            _tty,
            _stat,
            _start,
            _time,
            _command,
        ) = list(range(11))
        output_array = []

        output = (
            "%s".ljust(15 - len("USER")) % "USER",
            "%s".ljust(8 - len("PID")) % "PID",
            "%s".ljust(13 - len("%CPU")) % "%CPU",
            "%s".ljust(13 - len("%MEM")) % "%MEM",
            "%s".ljust(12 - len("VSZ")) % "VSZ",
            "%s".ljust(12 - len("RSS")) % "RSS",
            "%s".ljust(10 - len("TTY")) % "TTY",
            "%s".ljust(8 - len("STAT")) % "STAT",
            "%s".ljust(8 - len("START")) % "START",
            "%s".ljust(8 - len("TIME")) % "TIME",
            "%s".ljust(30 - len("COMMAND")) % "COMMAND",
        )
        output_array.append(output)
        if self.protocol.user.server.process:
            for single_ps in self.protocol.user.server.process:
                output = (
                    "%s".ljust(15 - len(str(single_ps["USER"])))
                    % str(single_ps["USER"]),
                    "%s".ljust(8 - len(str(single_ps["PID"]))) % str(single_ps["PID"]),
                    "%s".ljust(13 - len(str(round(single_ps["CPU"], 2))))
                    % str(round(single_ps["CPU"], 2)),
                    "%s".ljust(13 - len(str(round(single_ps["MEM"], 2))))
                    % str(round(single_ps["MEM"], 2)),
                    "%s".ljust(12 - len(str(single_ps["VSZ"]))) % str(single_ps["VSZ"]),
                    "%s".ljust(12 - len(str(single_ps["RSS"]))) % str(single_ps["RSS"]),
                    "%s".ljust(10 - len(str(single_ps["TTY"]))) % str(single_ps["TTY"]),
                    "%s".ljust(8 - len(str(single_ps["STAT"])))
                    % str(single_ps["STAT"]),
                    "%s".ljust(8 - len(str(single_ps["START"])))
                    % str(single_ps["START"]),
                    "%s".ljust(8 - len(str(single_ps["TIME"])))
                    % str(single_ps["TIME"]),
                    "%s".ljust(30 - len(str(single_ps["COMMAND"])))
                    % str(single_ps["COMMAND"]),
                )
                output_array.append(output)
            process = random.randint(4000, 8000)
            output = (
                "%s".ljust(15 - len("root")) % "root",
                "%s".ljust(8 - len(str(process))) % str(process),
                "%s".ljust(13 - len("0.0")) % "0.0",
                "%s".ljust(13 - len("0.1")) % "0.1",
                "%s".ljust(12 - len("5416")) % "5416",
                "%s".ljust(12 - len("1024")) % "1024",
                "%s".ljust(10 - len("?")) % "?",
                "%s".ljust(8 - len("Ss")) % "Ss",
                "%s".ljust(8 - len("Jul22")) % "Jul22",
                "%s".ljust(8 - len("0:00")) % "0:00",
                "%s".ljust(30 - len("/usr/sbin/sshd: %s@pts/0"))
                % "/usr/sbin/sshd: %s@pts/0"
                % user,
            )
            output_array.append(output)
            process = process + 5
            output = (
                "%s".ljust(15 - len(user)) % user,
                "%s".ljust(8 - len(str(process))) % str(process),
                "%s".ljust(13 - len("0.0")) % "0.0",
                "%s".ljust(13 - len("0.1")) % "0.1",
                "%s".ljust(12 - len("2925")) % "5416",
                "%s".ljust(12 - len("1541")) % "1024",
                "%s".ljust(10 - len("pts/0")) % "pts/0",
                "%s".ljust(8 - len("Ss")) % "Ss",
                "%s".ljust(8 - len("06:30")) % "06:30",
                "%s".ljust(8 - len("0:00")) % "0:00",
                "%s".ljust(30 - len("bash")) % "-bash",
            )
            output_array.append(output)
            process = process + 2
            output = (
                "%s".ljust(15 - len(user)) % user,
                "%s".ljust(8 - len(str(process))) % str(process),
                "%s".ljust(13 - len("0.0")) % "0.0",
                "%s".ljust(13 - len("0.1")) % "0.1",
                "%s".ljust(12 - len("2435")) % "2435",
                "%s".ljust(12 - len("929")) % "929",
                "%s".ljust(10 - len("pts/0")) % "pts/0",
                "%s".ljust(8 - len("Ss")) % "Ss",
                "%s".ljust(8 - len("06:30")) % "06:30",
                "%s".ljust(8 - len("0:00")) % "0:00",
                "%s".ljust(30 - len("ps")) % "ps %s" % " ".join(self.args),
            )

            output_array.append(output)
        else:
            output_array = [
                (
                    "USER      ",
                    " PID",
                    " %CPU",
                    " %MEM",
                    "    VSZ",
                    "   RSS",
                    " TTY      ",
                    "STAT ",
                    "START",
                    "   TIME ",
                    "COMMAND",
                ),
                (
                    "root      ",
                    "   1",
                    "  0.0",
                    "  0.1",
                    "   2100",
                    "   688",
                    " ?        ",
                    "Ss   ",
                    "Nov06",
                    "   0:07 ",
                    "init [2]  ",
                ),
                (
                    "root      ",
                    "   2",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[kthreadd]",
                ),
                (
                    "root      ",
                    "   3",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[migration/0]",
                ),
                (
                    "root      ",
                    "   4",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[ksoftirqd/0]",
                ),
                (
                    "root      ",
                    "   5",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[watchdog/0]",
                ),
                (
                    "root      ",
                    "   6",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:17 ",
                    "[events/0]",
                ),
                (
                    "root      ",
                    "   7",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[khelper]",
                ),
                (
                    "root      ",
                    "  39",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[kblockd/0]",
                ),
                (
                    "root      ",
                    "  41",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[kacpid]",
                ),
                (
                    "root      ",
                    "  42",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[kacpi_notify]",
                ),
                (
                    "root      ",
                    " 170",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[kseriod]",
                ),
                (
                    "root      ",
                    " 207",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S    ",
                    "Nov06",
                    "   0:01 ",
                    "[pdflush]",
                ),
                (
                    "root      ",
                    " 208",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S    ",
                    "Nov06",
                    "   0:00 ",
                    "[pdflush]",
                ),
                (
                    "root      ",
                    " 209",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[kswapd0]",
                ),
                (
                    "root      ",
                    " 210",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[aio/0]",
                ),
                (
                    "root      ",
                    " 748",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[ata/0]",
                ),
                (
                    "root      ",
                    " 749",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[ata_aux]",
                ),
                (
                    "root      ",
                    " 929",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[scsi_eh_0]",
                ),
                (
                    "root      ",
                    "1014",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "D<   ",
                    "Nov06",
                    "   0:03 ",
                    "[kjournald]",
                ),
                (
                    "root      ",
                    "1087",
                    "  0.0",
                    "  0.1",
                    "   2288",
                    "   772",
                    " ?        ",
                    "S<s  ",
                    "Nov06",
                    "   0:00 ",
                    "udevd --daemon",
                ),
                (
                    "root      ",
                    "1553",
                    "  0.0",
                    "  0.0",
                    "      0",
                    "     0",
                    " ?        ",
                    "S<   ",
                    "Nov06",
                    "   0:00 ",
                    "[kpsmoused]",
                ),
                (
                    "root      ",
                    "2054",
                    "  0.0",
                    "  0.2",
                    "  28428",
                    "  1508",
                    " ?        ",
                    "Sl   ",
                    "Nov06",
                    "   0:01 ",
                    "/usr/sbin/rsyslogd -c3",
                ),
                (
                    "root      ",
                    "2103",
                    "  0.0",
                    "  0.2",
                    "   2628",
                    "  1196",
                    " tty1     ",
                    "Ss   ",
                    "Nov06",
                    "   0:00 ",
                    "/bin/login --     ",
                ),
                (
                    "root      ",
                    "2105",
                    "  0.0",
                    "  0.0",
                    "   1764",
                    "   504",
                    " tty2     ",
                    "Ss+  ",
                    "Nov06",
                    "   0:00 ",
                    "/sbin/getty 38400 tty2",
                ),
                (
                    "root      ",
                    "2107",
                    "  0.0",
                    "  0.0",
                    "   1764",
                    "   504",
                    " tty3     ",
                    "Ss+  ",
                    "Nov06",
                    "   0:00 ",
                    "/sbin/getty 38400 tty3",
                ),
                (
                    "root      ",
                    "2109",
                    "  0.0",
                    "  0.0",
                    "   1764",
                    "   504",
                    " tty4     ",
                    "Ss+  ",
                    "Nov06",
                    "   0:00 ",
                    "/sbin/getty 38400 tty4",
                ),
                (
                    "root      ",
                    "2110",
                    "  0.0",
                    "  0.0",
                    "   1764",
                    "   504",
                    " tty5     ",
                    "Ss+  ",
                    "Nov06",
                    "   0:00 ",
                    "/sbin/getty 38400 tty5",
                ),
                (
                    "root      ",
                    "2112",
                    "  0.0",
                    "  0.0",
                    "   1764",
                    "   508",
                    " tty6     ",
                    "Ss+  ",
                    "Nov06",
                    "   0:00 ",
                    "/sbin/getty 38400 tty6",
                ),
                (
                    "root      ",
                    "2133",
                    "  0.0",
                    "  0.1",
                    "   2180",
                    "   620",
                    " ?        ",
                    "S<s  ",
                    "Nov06",
                    "   0:00 ",
                    "dhclient3 -pf /var/run/dhclient.eth0.pid -lf /var/lib/dhcp3/dhclien",
                ),
                (
                    "root      ",
                    "4969",
                    "  0.0",
                    "  0.1",
                    "   5416",
                    "  1024",
                    " ?        ",
                    "Ss   ",
                    "Nov08",
                    "   0:00 ",
                    f"/usr/sbin/sshd: {user}@pts/0",
                ),
                (
                    "%s".ljust(8) % user,
                    "5673",
                    "  0.0",
                    "  0.2",
                    "   2924",
                    "  1540",
                    " pts/0    ",
                    "Ss   ",
                    "04:30",
                    "   0:00 ",
                    "-bash",
                ),
                (
                    "%s".ljust(8) % user,
                    "5679",
                    "  0.0",
                    "  0.1",
                    "   2432",
                    "   928",
                    " pts/0    ",
                    "R+   ",
                    "04:32",
                    "   0:00 ",
                    f"ps {' '.join(self.args)}",
                ),
            ]

        for i in range(len(output_array)):
            if i != 0:
                if "a" not in args and output_array[i][_user].strip() != user:
                    continue
                elif (
                    "a" not in args
                    and "x" not in args
                    and output_array[i][_tty].strip() != "pts/0"
                ):
                    continue
            line = [_pid, _tty, _time, _command]
            if "a" in args or "x" in args:
                line = [_pid, _tty, _stat, _time, _command]
            if "u" in args:
                line = [
                    _user,
                    _pid,
                    _cpu,
                    _mem,
                    _vsz,
                    _rss,
                    _tty,
                    _stat,
                    _start,
                    _time,
                    _command,
                ]
            s = "".join([output_array[i][x] for x in line])
            if "w" not in args:
                s = s[: self.columns()]
            self.write(f"{s}\n")


commands["/bin/ps"] = Command_ps
commands["ps"] = Command_ps
