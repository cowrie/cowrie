# SPDX-FileCopyrightText: 2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the cowrie.log observer factory: the observers it
# ABOUTME: produces must declare ILogObserver so twistd accepts them natively.

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from twisted.logger import ILogObserver

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_HONEYPOT_DOWNLOAD_PATH"] = tempfile.gettempdir()
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class LogObserverInterfaceTests(unittest.TestCase):
    """
    twistd's AppLogger only recognizes observers that declare
    twisted.logger.ILogObserver; anything else is wrapped in a legacy
    adapter with a deprecation warning.
    """

    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp()
        os.environ["COWRIE_HONEYPOT_LOG_PATH"] = self.dir

    def tearDown(self) -> None:
        del os.environ["COWRIE_HONEYPOT_LOG_PATH"]
        shutil.rmtree(self.dir)

    def test_logger_provides_ilogobserver(self) -> None:
        from cowrie.python.logfile import logger

        observer = logger()
        self.assertTrue(ILogObserver.providedBy(observer))

    def test_stdout_logger_provides_ilogobserver(self) -> None:
        from cowrie.python.logfile import stdoutLogger

        observer = stdoutLogger()
        self.assertTrue(ILogObserver.providedBy(observer))
