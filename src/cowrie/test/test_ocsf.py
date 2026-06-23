# SPDX-FileCopyrightText: 2026 JustSamAgain justsamagain@proton.me
#
# SPDX-License-Identifier: BSD-3-Clause

"""
Tests for the OCSF event mapping in cowrie.core.ocsf.

Each Cowrie event class maps onto a specific OCSF class/activity. These tests
pin the discriminator fields (class_uid, type_uid, activity_id, ...) and the
distinctive nested object for each event, so a regression in the mapping is
caught without depending on the runtime-generated metadata fields.
"""

from __future__ import annotations

import json
import unittest

from cowrie.core.ocsf import formatOCSF

SHA = "2638f1c1c2018567a46a4cae049dd90db2d468e1538d60d328f2707d071f73c5"

# A representative, post-emit() event for every mapped eventid.
EVENTS: dict[str, dict] = {
    "cowrie.session.connect": {
        "eventid": "cowrie.session.connect",
        "src_ip": "127.0.0.1",
        "src_port": 37434,
        "dst_ip": "127.0.0.1",
        "dst_port": 2222,
        "session": "0000000000000001",
        "protocol": "ssh",
        "message": "New connection",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:26.253618Z",
    },
    "cowrie.session.closed": {
        "eventid": "cowrie.session.closed",
        "duration": "4.5",
        "message": "Connection lost after 4.5 seconds",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:30.727510Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000001",
        "protocol": "ssh",
    },
    "cowrie.client.version": {
        "eventid": "cowrie.client.version",
        "version": "SSH-2.0-OpenSSH_9.6p1",
        "message": "Remote SSH version: SSH-2.0-OpenSSH_9.6p1",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:26.254213Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000001",
        "protocol": "ssh",
    },
    "cowrie.client.kex": {
        "eventid": "cowrie.client.kex",
        "hassh": "aae6b9604f6f3356543709a376d7f657",
        "hasshAlgorithms": "kex;enc;mac;comp",
        "kexAlgs": ["curve25519-sha256"],
        "keyAlgs": ["ssh-ed25519"],
        "encCS": ["aes128-ctr"],
        "macCS": ["hmac-sha2-256"],
        "compCS": ["none"],
        "langCS": [""],
        "message": "SSH client hassh fingerprint",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:26.254692Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000001",
        "protocol": "ssh",
    },
    "cowrie.login.success": {
        "eventid": "cowrie.login.success",
        "username": "admin",
        "password": "lol",
        "message": "login attempt [admin/lol] succeeded",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:29.620070Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000001",
        "protocol": "ssh",
    },
    "cowrie.login.failed": {
        "eventid": "cowrie.login.failed",
        "username": "root",
        "password": "root",
        "message": "login attempt [root/root] failed",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T15:08:24.195892Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000002",
        "protocol": "ssh",
    },
    "cowrie.command.input": {
        "eventid": "cowrie.command.input",
        "input": "uname -a",
        "message": "CMD: uname -a",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:30.726107Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000001",
        "protocol": "ssh",
    },
    "cowrie.command.failed": {
        "eventid": "cowrie.command.failed",
        "input": "xxxx ",
        "message": "Command not found: xxxx ",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T15:41:31.033255Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000003",
        "protocol": "ssh",
    },
    "cowrie.log.closed": {
        "eventid": "cowrie.log.closed",
        "ttylog": "var/lib/cowrie/tty/" + SHA,
        "size": 314,
        "shasum": SHA,
        "duplicate": True,
        "duration": "1.0",
        "message": "Closing TTY Log",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:30.726777Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000001",
        "protocol": "ssh",
    },
    "cowrie.session.file_download": {
        "eventid": "cowrie.session.file_download",
        "url": "http://198.51.100.5/x.sh",
        "outfile": "var/lib/cowrie/downloads/" + SHA,
        "shasum": SHA,
        "message": "Downloaded URL",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:30.000000Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000001",
        "protocol": "ssh",
    },
    "cowrie.session.file_upload": {
        "eventid": "cowrie.session.file_upload",
        "filename": "evil.sh",
        "duplicate": False,
        "url": "evil.sh",
        "outfile": SHA,
        "shasum": SHA,
        "destfile": "evil.sh",
        "message": "SCP Uploaded file",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:31.000000Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000001",
        "protocol": "ssh",
    },
    "cowrie.session.file_download.failed": {
        "eventid": "cowrie.session.file_download.failed",
        "url": "http://198.51.100.5/x.sh",
        "message": "Attempt to download file(s) from URL failed",
        "sensor": "honeypot-01",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-06-23T14:15:30.000000Z",
        "src_ip": "127.0.0.1",
        "session": "0000000000000001",
        "protocol": "ssh",
    },
}


class OCSFCommonTests(unittest.TestCase):
    """Invariants that hold for every mapped event."""

    def test_all_events_have_common_metadata(self) -> None:
        for eventid, event in EVENTS.items():
            with self.subTest(eventid=eventid):
                out = formatOCSF(event)
                # type_uid is always class_uid * 100 + activity_id.
                self.assertEqual(
                    out["type_uid"], out["class_uid"] * 100 + out["activity_id"]
                )
                # message passes through untouched.
                self.assertEqual(out["message"], event["message"])
                # eventid and session always land in unmapped.
                self.assertEqual(out["unmapped"]["eventid"], eventid)
                self.assertEqual(out["unmapped"]["session"], event["session"])
                # product carries the sensor uuid.
                self.assertEqual(out["metadata"]["product"]["uid"], event["uuid"])
                self.assertEqual(out["metadata"]["labels"], ["honeypot"])

    def test_raw_data_is_compact_sorted_json(self) -> None:
        for eventid, event in EVENTS.items():
            with self.subTest(eventid=eventid):
                out = formatOCSF(event)
                self.assertEqual(
                    out["raw_data"],
                    json.dumps(event, sort_keys=True, separators=(",", ":")),
                )

    def test_time_is_epoch_milliseconds(self) -> None:
        # 2026-06-23T14:15:26.253618Z -> 1782224126253
        out = formatOCSF(EVENTS["cowrie.session.connect"])
        self.assertEqual(out["time"], 1782224126253)


class OCSFSSHActivityTests(unittest.TestCase):
    """SSH Activity, class_uid 4007 (Network Activity)."""

    def _assert_ssh(self, out: dict) -> None:
        self.assertEqual(out["class_uid"], 4007)
        self.assertEqual(out["class_name"], "SSH Activity")
        self.assertEqual(out["category_uid"], 4)
        self.assertEqual(out["connection_info"]["direction_id"], 1)
        self.assertEqual(out["connection_info"]["protocol_name"], "ssh")

    def test_connect(self) -> None:
        out = formatOCSF(EVENTS["cowrie.session.connect"])
        self._assert_ssh(out)
        self.assertEqual(out["activity_id"], 1)
        self.assertEqual(out["type_uid"], 400701)
        self.assertEqual(out["src_endpoint"], {"ip": "127.0.0.1", "port": 37434})
        self.assertEqual(
            out["dst_endpoint"],
            {"hostname": "honeypot-01", "ip": "127.0.0.1", "port": 2222},
        )

    def test_session_closed(self) -> None:
        out = formatOCSF(EVENTS["cowrie.session.closed"])
        self._assert_ssh(out)
        self.assertEqual(out["activity_id"], 2)
        self.assertEqual(out["type_uid"], 400702)
        # duration "4.5" seconds -> 4500 ms.
        self.assertEqual(out["duration"], 4500)
        # No ports on this event: endpoints are sparse.
        self.assertEqual(out["src_endpoint"], {"ip": "127.0.0.1"})
        self.assertEqual(out["dst_endpoint"], {"hostname": "honeypot-01"})

    def test_client_version(self) -> None:
        out = formatOCSF(EVENTS["cowrie.client.version"])
        self._assert_ssh(out)
        self.assertEqual(out["activity_id"], 99)
        self.assertEqual(out["type_uid"], 400799)
        self.assertEqual(
            out["unmapped"]["client_version"], "SSH-2.0-OpenSSH_9.6p1"
        )

    def test_client_kex_hassh(self) -> None:
        out = formatOCSF(EVENTS["cowrie.client.kex"])
        self._assert_ssh(out)
        self.assertEqual(out["activity_id"], 99)
        self.assertEqual(
            out["client_hassh"]["fingerprint"],
            {
                "algorithm": "MD5",
                "algorithm_id": 1,
                "value": "aae6b9604f6f3356543709a376d7f657",
            },
        )
        self.assertEqual(out["client_hassh"]["algorithm"], "kex;enc;mac;comp")


class OCSFAuthenticationTests(unittest.TestCase):
    """Authentication, class_uid 3002 (Identity & Access Management)."""

    def test_login_success(self) -> None:
        out = formatOCSF(EVENTS["cowrie.login.success"])
        self.assertEqual(out["class_uid"], 3002)
        self.assertEqual(out["category_uid"], 3)
        self.assertEqual(out["type_uid"], 300201)
        self.assertEqual(out["status"], "Success")
        self.assertEqual(out["status_id"], 1)
        self.assertEqual(out["severity_id"], 3)
        self.assertTrue(out["is_remote"])
        # admin is a privileged name -> Admin (type_id 2).
        self.assertEqual(out["user"], {"name": "admin", "type_id": 2})
        self.assertEqual(out["unmapped"]["password"], "lol")
        self.assertIn(
            {"name": "user.name", "type_id": 4, "value": "admin"},
            out["observables"],
        )

    def test_login_failed(self) -> None:
        out = formatOCSF(EVENTS["cowrie.login.failed"])
        self.assertEqual(out["type_uid"], 300201)
        self.assertEqual(out["status"], "Failure")
        self.assertEqual(out["status_id"], 2)
        # Failed attempts are Info severity, successes are Medium.
        self.assertEqual(out["severity_id"], 1)
        self.assertEqual(out["user"], {"name": "root", "type_id": 2})

    def test_unprivileged_user_type(self) -> None:
        event = dict(EVENTS["cowrie.login.success"], username="bob")
        out = formatOCSF(event)
        self.assertEqual(out["user"], {"name": "bob", "type_id": 1})


class OCSFProcessActivityTests(unittest.TestCase):
    """Process Activity, class_uid 1007 (System Activity)."""

    def test_command_input(self) -> None:
        out = formatOCSF(EVENTS["cowrie.command.input"])
        self.assertEqual(out["class_uid"], 1007)
        self.assertEqual(out["category_uid"], 1)
        self.assertEqual(out["type_uid"], 100701)
        self.assertEqual(out["severity_id"], 2)
        self.assertEqual(out["device"], {"hostname": "honeypot-01", "type_id": 1})
        # cmd_line is the full input; name is the program (first token).
        self.assertEqual(out["process"]["cmd_line"], "uname -a")
        self.assertEqual(out["process"]["name"], "uname")
        # Process Activity carries no network endpoints / observables.
        self.assertNotIn("src_endpoint", out)
        self.assertNotIn("observables", out)
        # A successful command carries no failure status.
        self.assertNotIn("status", out)

    def test_command_failed(self) -> None:
        out = formatOCSF(EVENTS["cowrie.command.failed"])
        self.assertEqual(out["class_uid"], 1007)
        self.assertEqual(out["type_uid"], 100701)
        # Command-not-found is still a "Launch", flagged via status.
        self.assertEqual(out["activity_id"], 1)
        self.assertEqual(out["status"], "Failure")
        self.assertEqual(out["status_id"], 2)
        # Trailing whitespace: cmd_line keeps it, name is the first token.
        self.assertEqual(out["process"]["cmd_line"], "xxxx ")
        self.assertEqual(out["process"]["name"], "xxxx")


class OCSFFileSystemActivityTests(unittest.TestCase):
    """File System Activity, class_uid 1001 (System Activity)."""

    def _assert_fs(self, out: dict) -> None:
        self.assertEqual(out["class_uid"], 1001)
        self.assertEqual(out["category_uid"], 1)
        self.assertEqual(
            out["actor"], {"process": {"name": "cowrie", "uid": "cowrie"}}
        )
        self.assertEqual(out["device"], {"hostname": "honeypot-01", "type_id": 1})

    def test_log_closed(self) -> None:
        out = formatOCSF(EVENTS["cowrie.log.closed"])
        self._assert_fs(out)
        self.assertEqual(out["activity_id"], 99)
        self.assertEqual(out["type_uid"], 100199)
        self.assertEqual(out["duration"], 1000)
        self.assertEqual(out["file"]["size"], 314)
        self.assertEqual(out["file"]["path"], "var/lib/cowrie/tty/" + SHA)
        self.assertEqual(out["file"]["hashes"][0]["value"], SHA)
        self.assertEqual(out["unmapped"]["duplicate"], True)
        self.assertEqual(out["unmapped"]["src_ip"], "127.0.0.1")

    def test_file_download(self) -> None:
        out = formatOCSF(EVENTS["cowrie.session.file_download"])
        self._assert_fs(out)
        self.assertEqual(out["activity_id"], 1)
        self.assertEqual(out["type_uid"], 100101)
        self.assertEqual(out["file"]["path"], "var/lib/cowrie/downloads/" + SHA)
        # Downloads are stored under their digest; name is that basename.
        self.assertEqual(out["file"]["name"], SHA)
        # A real URL is surfaced as a URL observable (type_id 6).
        self.assertIn(
            {
                "name": "url.text",
                "type_id": 6,
                "value": "http://198.51.100.5/x.sh",
            },
            out["observables"],
        )

    def test_file_upload(self) -> None:
        out = formatOCSF(EVENTS["cowrie.session.file_upload"])
        self._assert_fs(out)
        self.assertEqual(out["type_uid"], 100101)
        # Uploads carry the attacker-supplied filename.
        self.assertEqual(out["file"]["name"], "evil.sh")
        # The "url" here is just the filename, not a URL -> no URL observable.
        urls = [o for o in out["observables"] if o["type_id"] == 6]
        self.assertEqual(urls, [])
        self.assertEqual(out["unmapped"]["destfile"], "evil.sh")
        self.assertEqual(out["unmapped"]["duplicate"], False)

    def test_file_download_failed(self) -> None:
        out = formatOCSF(EVENTS["cowrie.session.file_download.failed"])
        self._assert_fs(out)
        self.assertEqual(out["type_uid"], 100101)
        self.assertEqual(out["status"], "Failure")
        self.assertEqual(out["status_id"], 2)
        # Failed download created no file: object is minimal.
        self.assertEqual(out["file"], {"type_id": 1})


if __name__ == "__main__":
    unittest.main()
