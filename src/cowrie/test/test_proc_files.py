# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Generated /proc files must read like a live kernel's and agree with
# ABOUTME: the commands that report the same facts (uptime, nproc).

from __future__ import annotations

import os
import re
import unittest

from cowrie.core.config import CowrieConfig
from cowrie.shell import procfs, protocol
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"

PROMPT = b"root@unitTest:~# "


class ProcUptimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_proc_uptime_reports_seconds_since_boot(self) -> None:
        self.proto.lineReceived(b"cat /proc/uptime\n")
        output = self.tr.value()
        match = re.fullmatch(rb"(\d+\.\d\d) (\d+\.\d\d)\n" + re.escape(PROMPT), output)
        assert match is not None, output
        uptime, idle = float(match.group(1)), float(match.group(2))
        self.assertAlmostEqual(uptime, self.proto.uptime(), delta=2)
        # Idle time is summed over the CPUs, so it can exceed the uptime.
        self.assertGreater(idle, 0)


class BootOffsetTests(unittest.TestCase):
    """The emulated machine booted before cowrie started, so a restarted
    honeypot does not report a few seconds of uptime."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.proto.getProtoTransport().factory.starttime = 1_000_000.0
        protocol.boot_offset.cache_clear()
        self.addCleanup(protocol.boot_offset.cache_clear)

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def test_configured_offset(self) -> None:
        CowrieConfig.set("honeypot", "boot_offset", "86400")
        self.addCleanup(CowrieConfig.remove_option, "honeypot", "boot_offset")
        self.assertEqual(self.proto.boot_time(), 1_000_000.0 - 86400)

    def test_default_offset_is_between_one_and_ninety_days(self) -> None:
        offset = 1_000_000.0 - self.proto.boot_time()
        self.assertGreaterEqual(offset, 86400)
        self.assertLessEqual(offset, 90 * 86400)

    def test_offset_is_the_same_for_every_session(self) -> None:
        other = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        other.makeConnection(FakeTransport("", "31338"))
        self.addCleanup(other.connectionLost)
        other.getProtoTransport().factory.starttime = 1_000_000.0
        self.assertEqual(other.boot_time(), self.proto.boot_time())


# The check a probing bot ran on nitrogen (2026-11): the shell reads its own
# stat and status through /proc/self and compares the PIDs with $$.
BOT_PROC_CHECK = (
    b"if IFS=' ' read -r _filter_pid _filter_rest < /proc/self/stat; then "
    b"_filter_status_pid=NA; _filter_ns=NA; _filter_status_ok=0; "
    b"if [ -r /proc/self/status ]; then _filter_status_ok=1; "
    b"while IFS=: read -r _filter_key _filter_values; do "
    b'case "$_filter_key" in Pid) _filter_status_pid=$_filter_values;; '
    b"NSpid) _filter_ns=$_filter_values;; esac; done < /proc/self/status; fi; "
    b"printf '%s|%s|%s|%s|%s|%s|%s\\n' 'check' \"$$\" \"$_filter_pid\" "
    b'"$((6*7))" "$_filter_status_pid" "$_filter_ns" "$_filter_status_ok"; '
    b"else printf '%s\\n' 'check:NA'; fi"
)

# The check a telnet bot ran on a honeypot of ours (2026-11): it logs in, runs
# this line and leaves when nothing comes back.
BOT_CMDLINE_CHECK = b"cd /proc && cat self/cmdline"

# The lines of /proc/<pid>/status in Linux 6.1 (fs/proc/array.c,
# fs/proc/task_mmu.c), for a process with memory and no NUMA cpuset.
STATUS_KEYS_6_1 = [
    "Name", "Umask", "State", "Tgid", "Ngid", "Pid", "PPid", "TracerPid",
    "Uid", "Gid", "FDSize", "Groups", "NStgid", "NSpid", "NSpgid", "NSsid",
    "VmPeak", "VmSize", "VmLck", "VmPin", "VmHWM", "VmRSS", "RssAnon",
    "RssFile", "RssShmem", "VmData", "VmStk", "VmExe", "VmLib", "VmPTE",
    "VmSwap", "HugetlbPages", "CoreDumping", "THP_enabled", "Threads", "SigQ",
    "SigPnd", "ShdPnd", "SigBlk", "SigIgn", "SigCgt", "CapInh", "CapPrm",
    "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters",
    "Speculation_Store_Bypass", "SpeculationIndirectBranch", "Cpus_allowed",
    "Cpus_allowed_list", "Mems_allowed", "Mems_allowed_list",
    "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches",
]  # fmt: skip


class ProcSelfTests(unittest.TestCase):
    """/proc/self is the process that opens it: the shell for a builtin's
    redirection, the command itself for a command that opens the file."""

    def setUp(self) -> None:
        self.proto = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        self.proto.makeConnection(self.tr)
        self.tr.clear()

    def tearDown(self) -> None:
        self.proto.connectionLost()

    def run_line(self, line: bytes) -> bytes:
        """Send one line, return only the bytes it produced (prompt stripped)."""
        self.tr.clear()
        self.proto.lineReceived(line)
        out: bytes = self.tr.value()
        if out.endswith(PROMPT):
            out = out[: -len(PROMPT)]
        return out

    def test_bot_check_sees_the_shell_pid(self) -> None:
        pid = self.run_line(b"echo $$").strip()
        self.assertEqual(
            self.run_line(BOT_PROC_CHECK),
            b"check|%s|%s|42|\t%s|\t%s|1\n" % (pid, pid, pid, pid),
        )

    def test_bot_check_in_sh_c_sees_the_inner_shell(self) -> None:
        script = BOT_PROC_CHECK.replace(b"'", b"'\\''")
        out = self.run_line(b"sh -c 'echo $$; " + script + b"'")
        pid, check = out.split(b"\n", 1)
        self.assertEqual(check, b"check|%s|%s|42|\t%s|\t%s|1\n" % ((pid,) * 4))

    def test_command_reads_its_own_stat(self) -> None:
        shell = self.run_line(b"echo $$").strip()
        fields = self.run_line(b"cat /proc/self/stat").split()
        self.assertEqual(len(fields), 52)
        self.assertNotEqual(fields[0], shell)
        self.assertEqual(fields[1], b"(cat)")
        self.assertEqual(fields[2], b"R")
        self.assertEqual(fields[3], shell)

    def test_stat_start_time_is_after_boot(self) -> None:
        fields = self.run_line(b"cat /proc/self/stat").split()
        # Field 22 is the start time in clock ticks (100 a second) after boot.
        start_ticks = int(fields[21])
        self.assertGreater(start_ticks, 0)
        self.assertLessEqual(start_ticks, self.proto.uptime() * 100 + 1)

    def test_status_has_the_linux_6_1_fields(self) -> None:
        shell = self.run_line(b"echo $$").strip().decode()
        lines = self.run_line(b"cat /proc/self/status").decode().splitlines()
        status = dict(line.split(":", 1) for line in lines)
        self.assertEqual(list(status), STATUS_KEYS_6_1)
        self.assertEqual(status["Name"], "\tcat")
        self.assertEqual(status["PPid"], f"\t{shell}")
        self.assertEqual(status["Pid"], status["Tgid"])
        self.assertEqual(status["Pid"], status["NSpid"])
        self.assertEqual(status["Uid"], "\t0\t0\t0\t0")
        self.assertEqual(status["Gid"], "\t0\t0\t0\t0")
        # /proc/cpuinfo lists two CPUs.
        self.assertEqual(status["Cpus_allowed"], "\t3")
        self.assertEqual(status["Cpus_allowed_list"], "\t0-1")

    def test_bot_check_sees_its_own_cmdline(self) -> None:
        self.tr.clear()
        self.proto.lineReceived(BOT_CMDLINE_CHECK)
        self.assertEqual(self.tr.value(), b"cat\0self/cmdline\0root@unitTest:/proc# ")

    def test_cmdline_has_the_name_the_command_was_invoked_by(self) -> None:
        self.assertEqual(
            self.run_line(b"cat /proc/self/cmdline"), b"cat\0/proc/self/cmdline\0"
        )
        self.assertEqual(
            self.run_line(b"/bin/cat /proc/self/cmdline"),
            b"/bin/cat\0/proc/self/cmdline\0",
        )

    def test_comm_agrees_with_stat(self) -> None:
        self.assertEqual(self.run_line(b"/bin/cat /proc/self/comm"), b"cat\n")
        fields = self.run_line(b"/bin/cat /proc/self/stat").split()
        self.assertEqual(fields[1], b"(cat)")

    def test_builtin_reads_the_shell_comm(self) -> None:
        out = self.run_line(b'read -r name < /proc/self/comm; echo "$name"')
        self.assertEqual(out, b"bash\n")

    def test_login_shell_cmdline(self) -> None:
        # Nothing is running: the reading process is the login shell itself.
        self.assertEqual(procfs.self_cmdline(self.proto), b"-bash\0")

    def test_builtin_reads_the_shell_status(self) -> None:
        out = self.run_line(
            b"while IFS=: read -r k v; do "
            b'[ "$k" = Name ] && echo "$v"; done < /proc/self/status'
        )
        self.assertEqual(out, b"\tbash\n")


if __name__ == "__main__":
    unittest.main()
