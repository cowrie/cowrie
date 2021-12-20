# Copyright (c) 2015 Michel Oosterhof <michel@oosterhof.net>
# All rights reserved.
from __future__ import absolute_import, division

import getopt
from typing import Dict

from cowrie.shell.command import HoneyPotCommand


class command_free(HoneyPotCommand):
    """/usr/bin/free"""
    HELP = (
        "\n"
        "Usage:\n"
        " free [options]\n"
        "\n"
        "Options:\n"
        " -b, --bytes         show output in bytes\n"
        " -k, --kilo          show output in kilobytes\n"
        " -m, --mega          show output in megabytes\n"
        " -g, --giga          show output in gigabytes\n"
        "     --tera          show output in terabytes\n"
        " -h, --human         show human-readable output\n"
        "     --si            use powers of 1000 not 1024\n"
        " -l, --lohi          show detailed low and high memory statistics\n"
        " -o, --old           use old format (without -/+buffers/cache line)\n"
        " -t, --total         show total for RAM + swap\n"
        " -s N, --seconds N   repeat printing every N seconds\n"
        " -c N, --count N     repeat printing N times, then exit\n"
        "\n"
        "     --help     display this help and exit\n"
        " -V, --version  output version information and exit\n"
        "\n"
        "For more details see free(1).\n"
    )
    VERSION = "free from procps-ng 3.3.9\n"
    MEMINFO_KEYS = ["MemTotal", "MemFree", "Shmem", "Buffers", "Cached", "SwapTotal", "SwapFree"]
    OUTPUT_FMT = (
        "             total       used       free     shared    buffers     cached\n"
        "Mem:    {MemTotal:>10} {MemUsed:>10} {MemFree:>10} {Shmem:>10} {Buffers:>10} {Cached:>10}\n"
        "-/+ buffers/cache\n"
        "Swap:   {SwapTotal:>10} {SwapUsed:>10} {SwapFree:>10}\n"
    )

    def call(self):
        try:
            opts, args = getopt.getopt(self.args, "hbkmgVt",
                                       ["human", "bytes", "kilo", "mega", "giga", "tera", "help", "version", "total"])
        except getopt.GetoptError as e:
            self.errorWrite("free: invalid option -- {}\n".format(e.opt))
            self._help()
            return

        meminfo = self._read_meminfo()

        tmp = [oa[0] for oa in opts]
        if not tmp:
            self._print_stats(meminfo)
            return

        if "--help" in tmp:
            self._help()
            return
        if "--version" in tmp or "-V" in tmp:
            self._version()
            return
        if "--human" in tmp or "-h" in tmp:
            self._print_stats_for_human(meminfo)
            return
        if "--total" in tmp or "-t" in tmp:
            self._total(meminfo)
            return

        for opt, arg in opts:
            if opt in ("-b", "--bytes"):
                self._print_stats(meminfo, fmt="bytes")
                break
            if opt in ("-k", "--kilo"):
                self._print_stats(meminfo, fmt="kilo")
                break
            if opt in ("-m", "--mega"):
                self._print_stats(meminfo, fmt="mega")
                break
            if opt in ("-g", "--giga"):
                self._print_stats(meminfo, fmt="giga")
                break
            if opt == "--tera":
                self._print_stats(meminfo, fmt="tera")
                break

    def _print_stats(self, meminfo: Dict[str, int], fmt: str = "kilo") -> None:
        if fmt == "bytes":
            for key, value in meminfo.items():
                meminfo[key] = value * 1024
        # elif fmt == "kilo":  # by default
        elif fmt == "mega":
            for key, value in meminfo.items():
                meminfo[key] = value // 1024
        elif fmt == "giga":
            for key, value in meminfo.items():
                meminfo[key] = (value // 1024) // 1024
        elif fmt == "tera":
            for key, value in meminfo.items():
                meminfo[key] = ((value // 1024) // 1024) // 1024
        self.write(command_free.OUTPUT_FMT.format(**meminfo))

    def _print_stats_for_human(self, meminfo: Dict[str, int]) -> None:
        magnitude = ["B", "M", "G", "T", "Z"]
        tmp = {}
        for key, value in meminfo.items():
            index = 0
            value = float(value)            # src/cowrie/commands/free.py:114:17: error: Incompatible types in assignment (expression has type "float", variable has type "int")  [assignment]
            while value >= 1024 and index < len(magnitude):
                value /= 1024.0
                index += 1
            tmp[key] = "{:g}{}".format(round(value, 1), magnitude[index])
        self.write(command_free.OUTPUT_FMT.format(**tmp))

    def _read_meminfo(self) -> Dict[str, int]:
        r = {}
        data = self.fs.file_contents("/proc/meminfo")
        for line in data.decode().splitlines():
            key, value = line.split(":")
            if key in command_free.MEMINFO_KEYS:
                r[key] = int(value[:value.rfind(" ")])
        r["MemUsed"] = r["MemTotal"] - r["MemFree"]
        r["SwapUsed"] = r["SwapTotal"] - r["SwapFree"]
        return r

    def _total(self, meminfo: Dict[str, int]) -> None:
        total_total = meminfo["MemTotal"] + meminfo["SwapTotal"]    # )
        total_used = meminfo["MemUsed"] + meminfo["SwapUsed"]
        total_free = meminfo["MemFree"] + meminfo["SwapFree"]
        self.write(command_free.OUTPUT_FMT.format(**meminfo))
        self.write("Total:  {:>10} {:>10} {:>10}\n".format(total_total, total_used, total_free))

    def _help(self) -> None:
        self.write(command_free.HELP)

    def _version(self) -> None:
        self.write(command_free.VERSION)


commands = {
    "free": command_free,
    "/usr/bin/free": command_free,
}
