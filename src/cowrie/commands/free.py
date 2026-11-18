# SPDX-FileCopyrightText: 2015-2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: The free command: reports memory and swap use from the emulated
# ABOUTME: machine's /proc/meminfo.

"""
This module ...
"""

from __future__ import annotations

import getopt

from cowrie.shell.command import HoneyPotCommand
from cowrie.shell.fs import FileNotFound

commands = {}

HEADER = (
    "               total        used        free      shared  buff/cache   available\n"
)

# Unit options and the power of 1024 that a byte count is divided by.
UNIT_EXPONENTS = {"-b": 0, "-k": 1, "-m": 2, "-g": 3}

HUMAN_UNITS = "KMGTP"


def scale_size(kib: int, exponent: int, human: bool) -> str:
    """
    Format a size given in kB the way procps 4.0.2's free does: a whole number
    of the chosen unit, or with -h the shortest of "1.5Gi" or "974Mi" that
    fits in five characters.
    """
    size = kib * 1024
    if not human:
        return str(size // 1024**exponent)
    if len(f"{size}B") <= 4:
        return f"{size}B"
    text = ""
    for power, unit in enumerate(HUMAN_UNITS, start=1):
        value = size / 1024**power
        text = f"{value:.1f}{unit}i"
        if len(text) <= 5:
            return text
        text = f"{int(value)}{unit}i"
        if len(text) <= 5:
            return text
    return text


class Command_free(HoneyPotCommand):
    """
    free
    """

    def call(self) -> None:
        # Parse options or display no files
        try:
            opts, _args = getopt.getopt(self.args, "bkmgh")
        except getopt.GetoptError:
            self.do_free()
            return

        exponent = 1
        human = False
        for o, _a in opts:
            if o == "-h":
                human = True
            else:
                exponent = UNIT_EXPONENTS[o]
        self.do_free(exponent, human)

    def do_free(self, exponent: int = 1, human: bool = False) -> None:
        """
        print free statistics
        """

        # Get the emulated machine's memstats
        try:
            stats = self.get_free_stats()
        except FileNotFound:
            self.errorWrite(
                "free: Memory information file /proc/meminfo does not exist\n"
            )
            self.exit_code = 1
            return

        # Derived figures as procps 4.0.2 computes them
        available = stats["MemAvailable"]
        if available > stats["MemTotal"]:
            available = stats["MemFree"]
        used = stats["MemTotal"] - available
        if used < 0:
            used = stats["MemTotal"] - stats["MemFree"]
        buff_cache = stats["Buffers"] + stats["Cached"] + stats["SReclaimable"]
        swap_used = stats["SwapTotal"] - stats["SwapFree"]

        def row(label: str, sizes: list[int]) -> str:
            cells = [scale_size(size, exponent, human) for size in sizes]
            return f"{label:<9}" + " ".join(f"{cell:>11}" for cell in cells) + "\n"

        self.write(
            HEADER
            + row(
                "Mem:",
                [
                    stats["MemTotal"],
                    used,
                    stats["MemFree"],
                    stats["Shmem"],
                    buff_cache,
                    available,
                ],
            )
            + row("Swap:", [stats["SwapTotal"], swap_used, stats["SwapFree"]])
        )

    def get_free_stats(self) -> dict[str, int]:
        """
        Get the free stats from the emulated /proc/meminfo.

        Like procps, a field that is missing or unreadable counts as 0, and a
        kernel without MemAvailable reports MemFree as available.
        Raises FileNotFound when /proc/meminfo does not exist.
        """
        mem_info_map = dict.fromkeys(
            [
                "Buffers",
                "Cached",
                "SReclaimable",
                "MemTotal",
                "MemFree",
                "SwapTotal",
                "SwapFree",
                "Shmem",
                "MemAvailable",
            ],
            0,
        )
        meminfo = self.fs.file_contents("/proc/meminfo").decode(errors="replace")
        for line in meminfo.splitlines():
            key, _, value = line.partition(":")
            fields = value.split()
            if key in mem_info_map and fields and fields[0].isdigit():
                mem_info_map[key] = int(fields[0])

        if mem_info_map["MemAvailable"] == 0:
            mem_info_map["MemAvailable"] = mem_info_map["MemFree"]

        # Sizes are in kB, as /proc/meminfo gives them
        return mem_info_map


commands["/usr/bin/free"] = Command_free
commands["free"] = Command_free
