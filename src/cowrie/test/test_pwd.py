# SPDX-FileCopyrightText: 2026 sudu787
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests that a session user missing from /etc/passwd gets a uid fixed
# ABOUTME: by the username, without reseeding the process-wide random module.

from __future__ import annotations

import os
import random
import unittest

from cowrie.shell.pwd import Passwd

os.environ["COWRIE_HONEYPOT_DATA_PATH"] = "data"
os.environ["COWRIE_SHELL_FILESYSTEM"] = "src/cowrie/data/fs.pickle"


class SetPwEntryTests(unittest.TestCase):
    def test_uid_is_fixed_by_the_username(self) -> None:
        # The uids the global-seed implementation gave these names.
        for name, uid in (("admin", 9673), ("ubnt", 2708), ("oracle", 6373)):
            with self.subTest(name=name):
                e = Passwd().setpwentry(name)
                self.assertEqual((e["pw_uid"], e["pw_gid"]), (uid, uid))

    def test_global_random_state_is_untouched(self) -> None:
        # The username is attacker-chosen; it must not reseed the random
        # module every concurrent session draws from. Issue #40457.
        before = random.getstate()
        Passwd().setpwentry("admin")
        self.assertEqual(random.getstate(), before)


if __name__ == "__main__":
    unittest.main()
