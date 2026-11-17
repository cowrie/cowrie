# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Generated /proc files that describe the process reading them
# ABOUTME: (/proc/self/stat and status), in the format of Linux 6.1.

"""
/proc/self is the process that opens it. In cowrie that is the process on top
of the session's cmdstack at the moment of the read: the shell, when a builtin
redirects from the file (``read x < /proc/self/stat``), or the command itself
when it opens the file (``cat /proc/self/stat``).

The values that identify the process (PID, parent, name, owner, start time)
are real. The rest (memory use, addresses, counters) are plausible values for a
small process, varied per PID the way address randomisation varies them.
"""

from __future__ import annotations

import random
import time
from typing import Any

from cowrie.shell import fs

# Clock ticks per second (USER_HZ), the unit of the times in /proc/<pid>/stat.
USER_HZ = 100

# tty_nr of /dev/pts/0 (major 136, minor 0): the terminal cowrie reports for an
# interactive session.
PTS_0 = 136 << 8

# Every capability, for root: CAP_LAST_CAP is 40 in Linux 6.1.
ALL_CAPS = "000001ffffffffff"
NO_CAPS = "0000000000000000"


def cpu_count(filesystem: Any) -> int:
    """The number of CPUs listed in the emulated /proc/cpuinfo."""
    try:
        cpuinfo = filesystem.file_contents("/proc/cpuinfo")
    except (fs.FileNotFound, IsADirectoryError):
        cpuinfo = b""
    processors = [x for x in cpuinfo.splitlines() if x.startswith(b"processor")]
    return max(1, len(processors))


def cpu_mask(cpus: int) -> str:
    """A bitmap of CPUs 0..cpus-1 as the kernel prints it (%*pb): hex, in
    comma-separated groups of 32 bits, the first group only as wide as its
    bits need."""
    mask = (1 << cpus) - 1
    groups = []
    for _ in range((cpus + 31) // 32):
        groups.append(mask & 0xFFFFFFFF)
        mask >>= 32
    groups.reverse()
    first_bits = cpus % 32 or 32
    text = [f"{groups[0]:0{(first_bits + 3) // 4}x}"]
    text.extend(f"{group:08x}" for group in groups[1:])
    return ",".join(text)


def cpu_list(cpus: int) -> str:
    """CPUs 0..cpus-1 as the kernel prints a CPU list (%*pbl)."""
    return "0" if cpus == 1 else f"0-{cpus - 1}"


def reading_process(protocol: Any) -> Any:
    """The process that is reading /proc/self: the top of the cmdstack."""
    return protocol.cmdstack[-1]


def session_ids(protocol: Any, pid: int) -> tuple[int, int, int]:
    """The process group, session and terminal (tty_nr, foreground group) of
    a process in this session. Every process is counted in the login shell's
    session and process group."""
    session = protocol.cmdstack[0].pid if protocol.cmdstack else pid
    if getattr(protocol.terminal, "has_pty", True):
        return session, session, PTS_0
    return session, session, 0


def self_stat(protocol: Any) -> bytes:
    """/proc/self/stat for the reading process."""
    process = reading_process(protocol)
    pgrp, session, tty_nr = session_ids(protocol, process.pid)
    tpgid = pgrp if tty_nr else -1
    start_ticks = int((process.start_time - protocol.boot_time()) * USER_HZ)
    rnd = random.Random(process.pid)
    # Addresses of the code, data and stack segments, which differ per
    # process because of address space randomisation.
    start_code = (0x550000000 + rnd.randrange(0x10000000)) << 12
    start_stack = (0x7FFC00000 + rnd.randrange(0x400000)) << 12
    elapsed = max(0, int((time.time() - process.start_time) * USER_HZ))
    fields = [
        process.pid,
        f"({process.comm})",
        "R",  # it is running: it is reading this file
        process.ppid,
        pgrp,
        session,
        tty_nr,
        tpgid,
        4194304,  # flags: PF_RANDOMIZE
        rnd.randrange(150, 700),  # minor faults
        0,
        0,
        0,
        min(elapsed, rnd.randrange(0, 3)),  # user time
        0,
        0,
        0,
        20,  # priority
        0,  # nice
        1,  # threads
        0,
        start_ticks,
        rnd.randrange(2000, 2800) * 4096 * 2,  # virtual memory size
        rnd.randrange(250, 400) * 4,  # resident pages
        18446744073709551615,  # RLIMIT_RSS: unlimited
        start_code,
        start_code + 0x10E281,  # end of code
        start_stack,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        17,  # exit signal: SIGCHLD
        rnd.randrange(cpu_count(protocol.fs)),  # last CPU
        0,
        0,
        0,
        0,
        0,
        start_code + 0x1FD448,  # start of data
        start_code + 0x20A104,  # end of data
        start_code + 0x14F5D000,  # start of heap
        start_stack + 0x469,  # arguments
        start_stack + 0x47D,
        start_stack + 0x47D,  # environment
        start_stack + 0x15D9,
        0,
    ]
    return " ".join(str(field) for field in fields).encode() + b"\n"


def self_status(protocol: Any) -> bytes:
    """/proc/self/status for the reading process."""
    process = reading_process(protocol)
    _pgrp, session, _tty = session_ids(protocol, process.pid)
    uid = process.user["uid"]
    gid = process.user["gid"]
    caps = ALL_CAPS if uid == 0 else NO_CAPS
    cpus = cpu_count(protocol.fs)
    rnd = random.Random(process.pid)
    size = rnd.randrange(5000, 18000)
    rss = rnd.randrange(1000, 5000)
    anon = rnd.randrange(100, 800)
    lines = [
        ("Name", process.comm),
        ("Umask", "0022"),
        ("State", "R (running)"),
        ("Tgid", process.pid),
        ("Ngid", 0),
        ("Pid", process.pid),
        ("PPid", process.ppid),
        ("TracerPid", 0),
        ("Uid", f"{uid}\t{uid}\t{uid}\t{uid}"),
        ("Gid", f"{gid}\t{gid}\t{gid}\t{gid}"),
        ("FDSize", 64),
        ("Groups", f"{gid} "),
        ("NStgid", process.pid),
        ("NSpid", process.pid),
        ("NSpgid", session),
        ("NSsid", session),
        ("VmPeak", f"{size:8d} kB"),
        ("VmSize", f"{size:8d} kB"),
        ("VmLck", f"{0:8d} kB"),
        ("VmPin", f"{0:8d} kB"),
        ("VmHWM", f"{rss:8d} kB"),
        ("VmRSS", f"{rss:8d} kB"),
        ("RssAnon", f"{anon:8d} kB"),
        ("RssFile", f"{rss - anon:8d} kB"),
        ("RssShmem", f"{0:8d} kB"),
        ("VmData", f"{rnd.randrange(300, 3000):8d} kB"),
        ("VmStk", f"{132:8d} kB"),
        ("VmExe", f"{rnd.randrange(20, 1100):8d} kB"),
        ("VmLib", f"{rnd.randrange(1500, 6400):8d} kB"),
        ("VmPTE", f"{rnd.randrange(40, 80):8d} kB"),
        ("VmSwap", f"{0:8d} kB"),
        ("HugetlbPages", f"{0:8d} kB"),
        ("CoreDumping", 0),
        ("THP_enabled", 1),
        ("Threads", 1),
        ("SigQ", "0/15362"),
        ("SigPnd", "0000000000000000"),
        ("ShdPnd", "0000000000000000"),
        ("SigBlk", "0000000000000000"),
        ("SigIgn", "0000000000000000"),
        ("SigCgt", "0000000000000000"),
        ("CapInh", NO_CAPS),
        ("CapPrm", caps),
        ("CapEff", caps),
        ("CapBnd", ALL_CAPS),
        ("CapAmb", NO_CAPS),
        ("NoNewPrivs", 0),
        ("Seccomp", 0),
        ("Seccomp_filters", 0),
        ("Speculation_Store_Bypass", "thread vulnerable"),
        ("SpeculationIndirectBranch", "conditional enabled"),
        ("Cpus_allowed", cpu_mask(cpus)),
        ("Cpus_allowed_list", cpu_list(cpus)),
        ("Mems_allowed", "00000000,00000001"),
        ("Mems_allowed_list", 0),
        ("voluntary_ctxt_switches", rnd.randrange(0, 5)),
        ("nonvoluntary_ctxt_switches", rnd.randrange(0, 15)),
    ]
    return "".join(f"{key}:\t{value}\n" for key, value in lines).encode()
