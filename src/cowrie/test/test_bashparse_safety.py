# SPDX-FileCopyrightText: 2026 Friedjof Noweck <dev@noweck.info>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests the garbage-collection and timeout guards for the shell parser.
# ABOUTME: Keeps expensive Earley parses from retaining memory or blocking Cowrie.

from __future__ import annotations

import signal
import threading
import time
import unittest
from unittest.mock import patch

from cowrie.core.config import CowrieConfig
from cowrie.shell import bashparse
from cowrie.shell.bashparse import (
    BashParser,
    SyntaxError_,
    gc_collect_threshold,
    parse_timeout_seconds,
)


class FakeContext:
    def get_variable(self, name: str) -> str | None:
        return None

    def get_status(self) -> str:
        return "0"

    def command_substitution(self, source: str):
        raise NotImplementedError


class ShellParseSafetyConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        if not CowrieConfig.has_section("shell"):
            CowrieConfig.add_section("shell")

    def tearDown(self) -> None:
        CowrieConfig.remove_option("shell", "gc_collect_threshold")
        CowrieConfig.remove_option("shell", "parse_timeout_seconds")

    def test_gc_threshold_default_and_override(self) -> None:
        self.assertEqual(gc_collect_threshold(), 512)
        CowrieConfig.set("shell", "gc_collect_threshold", "1024")
        self.assertEqual(gc_collect_threshold(), 1024)

    def test_timeout_default_and_override(self) -> None:
        self.assertEqual(parse_timeout_seconds(), 10.0)
        CowrieConfig.set("shell", "parse_timeout_seconds", "2.5")
        self.assertEqual(parse_timeout_seconds(), 2.5)


class GarbageCollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = BashParser(FakeContext())

    def test_collects_at_threshold_after_success_and_parse_error(self) -> None:
        threshold = gc_collect_threshold()
        valid = "echo #" + "x" * (threshold - len("echo #"))
        invalid = "'" + "x" * threshold
        with patch("cowrie.shell.bashparse.gc.collect") as collect:
            self.parser.parse(valid)
            self.parser.parse(invalid)
        self.assertEqual(collect.call_count, 2)

    def test_does_not_collect_below_threshold(self) -> None:
        with patch("cowrie.shell.bashparse.gc.collect") as collect:
            self.parser.parse("echo hi")
        collect.assert_not_called()


@unittest.skipUnless(bashparse._HAS_PARSE_ALARM, "requires POSIX interval timers")
class ParseAlarmTests(unittest.TestCase):
    def setUp(self) -> None:
        if signal.getsignal(signal.SIGALRM) is not signal.SIG_DFL:
            self.skipTest("SIGALRM is owned by another component")
        if any(signal.getitimer(signal.ITIMER_REAL)):
            self.skipTest("real-time timer is owned by another component")
        self.parser = BashParser(FakeContext())

    def tearDown(self) -> None:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)

    def test_timeout_returns_syntax_error_and_cancels_alarm(self) -> None:
        original_parse = bashparse._parser.parse

        def slow_parse(line: str):
            time.sleep(0.2)
            return original_parse(line)

        with patch.object(bashparse._parser, "parse", side_effect=slow_parse):
            with patch(
                "cowrie.shell.bashparse.parse_timeout_seconds", return_value=0.05
            ):
                with patch("cowrie.shell.bashparse.gc.collect") as collect:
                    self.assertEqual(
                        self.parser.parse("echo hi"), [SyntaxError_(token="")]
                    )
        collect.assert_called_once()  # Timed-out input is collected even below 512.
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGALRM), signal.SIG_DFL)

    def test_handler_restored_if_timer_install_fails(self) -> None:
        with patch("cowrie.shell.bashparse.signal.setitimer", side_effect=ValueError):
            with self.assertRaises(ValueError):
                with bashparse._parse_alarm(1):
                    pass
        self.assertIs(signal.getsignal(signal.SIGALRM), signal.SIG_DFL)

    def test_real_earley_parse_times_out_and_next_command_works(self) -> None:
        # Valid input below max_input_size, yet expensive enough to outlast
        # the short test alarm. This exercises Lark's actual Earley work.
        line = "echo " + " ".join(f"arg{i}" for i in range(1600))
        self.assertLess(len(line), bashparse.max_input_size())
        with patch("cowrie.shell.bashparse.parse_timeout_seconds", return_value=0.05):
            self.assertEqual(self.parser.parse(line), [SyntaxError_(token="")])
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGALRM), signal.SIG_DFL)
        self.assertNotEqual(
            self.parser.parse("echo recovered"), [SyntaxError_(token="")]
        )

    def test_existing_alarm_handler_disables_timeout(self) -> None:
        def handler(signum: int, frame: object) -> None:
            return None

        signal.signal(signal.SIGALRM, handler)
        with bashparse._parse_alarm(0.01):
            time.sleep(0.03)
        self.assertIs(signal.getsignal(signal.SIGALRM), handler)

    def test_existing_real_time_alarm_disables_timeout(self) -> None:
        signal.setitimer(signal.ITIMER_REAL, 5)
        before, _ = signal.getitimer(signal.ITIMER_REAL)
        with bashparse._parse_alarm(0.01):
            time.sleep(0.03)
        remaining, _ = signal.getitimer(signal.ITIMER_REAL)
        self.assertGreater(remaining, 0)
        self.assertLess(remaining, before)

    def test_worker_thread_disables_timeout(self) -> None:
        errors: list[BaseException] = []

        def parse_in_worker() -> None:
            try:
                with bashparse._parse_alarm(0.01):
                    time.sleep(0.03)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=parse_in_worker)
        worker.start()
        worker.join()
        self.assertEqual(errors, [])
