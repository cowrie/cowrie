# SPDX-FileCopyrightText: 2026 Jari Huttunen <jari.tapani.huttunen@gmail.com>
#
# SPDX-License-Identifier: BSD-3-Clause

# ABOUTME: Tests for the AlienVault OTX output plugin: file and URL
# ABOUTME: submission, daily pulse reporting, deduplication and error handling.

from __future__ import annotations

import datetime
import json
import os
import shutil
import tempfile
import unittest
from typing import Any
from unittest.mock import Mock, patch

from treq.client import _convert_files
from twisted.internet import defer
from twisted.python.failure import Failure
from twisted.web.client import (
    FileBodyProducer,
    RequestGenerationFailed,
    RequestTransmissionFailed,
    ResponseNeverReceived,
)
from twisted.web.iweb import IBodyProducer

from cowrie.output.otx import (
    CREATE_PULSE,
    PATCH_PULSE,
    SUBMIT_FILE,
    SUBMIT_URL,
    Output,
)


def response(code: int = 200, body: str = "{}") -> Mock:
    result = Mock()
    result.code = code
    result.text.return_value = defer.succeed(body)
    return result


class OtxTestCase(unittest.TestCase):
    """Shared setup: a plugin instance pointed at temporary files."""

    def setUp(self) -> None:
        self.output = Output()
        self.output.api_key = "test-key"
        self.output.upload = True
        self.output.submit_url = True
        self.output.pulse = True
        self.output.pulse_name = "Cowrie honeypot samples"
        self.output.public = True
        self.output.tlp = "white"
        self.output.tags = ["cowrie", "honeypot"]
        self.output.group_ids = []
        self.output.include_src_ip = True
        self.output.include_url = True
        self.output.debug = False
        self.output.pulse_id = None
        self.output.pulse_date = None
        self.output.seen_sha256 = set()
        self.output.seen_urls = set()

        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.state_file = os.path.join(self.tmpdir, "otx_pulse.json")
        self.output._state_file = Mock(return_value=self.state_file)  # type: ignore[method-assign]

        self.shasum = "a" * 64
        self.sample = os.path.join(self.tmpdir, "sample.bin")
        with open(self.sample, "wb") as sample:
            sample.write(b"MZ fake malware")

        self.dispatch = Mock()
        self.output.dispatch = self.dispatch  # type: ignore[method-assign]

    def event(self, **overrides: Any) -> dict[str, Any]:
        event = {
            "eventid": "cowrie.session.file_download",
            "session": "session1",
            "src_ip": "8.8.8.8",
            "protocol": "ssh",
            "url": "http://example.com/malware.exe",
            "outfile": self.sample,
            "shasum": self.shasum,
        }
        event.update(overrides)
        return event

    def assert_resolved(self, deferred: defer.Deferred) -> None:
        results: list[Any] = []
        failures: list[Any] = []
        deferred.addCallbacks(results.append, failures.append)
        self.assertEqual(failures, [])
        self.assertEqual(len(results), 1)

    def _reported(self) -> dict[str, Any]:
        self.dispatch.assert_called()
        return dict(self.dispatch.call_args.kwargs)


class OtxWriteTests(OtxTestCase):
    """write() decides what to submit and deduplicates repeats."""

    def test_ignores_unrelated_events(self) -> None:
        with (
            patch.object(self.output, "submit_file") as submit_file,
            patch.object(self.output, "post_url") as post_url,
            patch.object(self.output, "report_pulse") as report_pulse,
        ):
            self.output.write({"eventid": "cowrie.session.connect"})
        submit_file.assert_not_called()
        post_url.assert_not_called()
        report_pulse.assert_not_called()

    def test_download_submits_file_url_and_pulse_once(self) -> None:
        event = self.event()
        with (
            patch.object(self.output, "submit_file") as submit_file,
            patch.object(self.output, "post_url") as post_url,
            patch.object(self.output, "report_pulse") as report_pulse,
        ):
            self.output.write(event)
            self.output.write(event)

        submit_file.assert_called_once_with(event, self.sample)
        post_url.assert_called_once_with(event, event["url"])
        report_pulse.assert_called_once_with(event)

    def test_disabled_actions_do_nothing(self) -> None:
        self.output.upload = False
        self.output.submit_url = False
        self.output.pulse = False
        with (
            patch.object(self.output, "submit_file") as submit_file,
            patch.object(self.output, "post_url") as post_url,
            patch.object(self.output, "report_pulse") as report_pulse,
        ):
            self.output.write(self.event())
        submit_file.assert_not_called()
        post_url.assert_not_called()
        report_pulse.assert_not_called()

    def test_skips_files_captured_before_start(self) -> None:
        old = datetime.datetime.now(datetime.UTC) - datetime.timedelta(minutes=10)
        os.utime(self.sample, (old.timestamp(), old.timestamp()))
        with (
            patch.object(self.output, "submit_file") as submit_file,
            patch.object(self.output, "report_pulse") as report_pulse,
        ):
            self.output.write(self.event())
        submit_file.assert_not_called()
        report_pulse.assert_not_called()

    def test_artifact_falls_back_to_download_path(self) -> None:
        # SCP upload events put only the hash in 'outfile'.
        stored = os.path.join(self.tmpdir, self.shasum)
        shutil.copy(self.sample, stored)
        event = self.event(outfile=self.shasum)
        with patch.dict(os.environ, {"COWRIE_HONEYPOT_DOWNLOAD_PATH": self.tmpdir}):
            self.assertEqual(self.output._artifact(event), stored)

    def test_missing_artifact_is_ignored(self) -> None:
        event = self.event(outfile=os.path.join(self.tmpdir, "missing"))
        with patch.object(self.output, "submit_file") as submit_file:
            self.output.write(event)
        submit_file.assert_not_called()

    def test_unexpected_failure_is_reported(self) -> None:
        """An exception outside REQUEST_FAILURES must not be left unhandled."""
        self.output.pulse = False
        self.output.submit_url = False
        failure = Failure(RuntimeError("boom"))
        with (
            patch.object(self.output, "_log"),
            patch.object(self.output, "submit_file", return_value=defer.fail(failure)),
        ):
            self.output.write(self.event())

        reported = self._reported()
        self.assertEqual(reported["action"], "file")
        self.assertEqual(reported["result"], "error")
        self.assertEqual(reported["sha256"], self.shasum)


class OtxSubmitFileTests(OtxTestCase):
    """submit_file() posts multipart data and reports the outcome."""

    def test_posts_multipart_with_api_key(self) -> None:
        with patch(
            "cowrie.output.otx.treq.post",
            return_value=defer.succeed(response()),
        ) as post:
            self.assert_resolved(self.output.submit_file(self.event(), self.sample))

        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["url"], SUBMIT_FILE)
        self.assertEqual(kwargs["headers"]["X-OTX-API-KEY"], "test-key")
        self.assertNotIn("Content-Type", kwargs["headers"])
        filename, content_type, upload = kwargs["files"]["file"]
        self.assertEqual(filename, "malware.exe")
        self.assertEqual(content_type, "application/octet-stream")
        self.assertIsInstance(upload, FileBodyProducer)

        # Drive treq's multipart conversion: the tuple order is
        # (filename, content_type, file object), and getting it wrong raises
        # TypeError before any request is sent.
        converted = list(_convert_files(kwargs["files"]))
        self.assertEqual(len(converted), 1)
        param, (name, ctype, producer) = converted[0]
        self.assertEqual(param, "file")
        self.assertEqual((name, ctype), ("malware.exe", "application/octet-stream"))
        self.assertTrue(IBodyProducer.providedBy(producer))

        reported = self._reported()
        self.assertEqual(reported["eventid"], "cowrie.otx.submitted")
        self.assertEqual(reported["action"], "file")
        self.assertEqual(reported["result"], "success")
        self.assertEqual(reported["sha256"], self.shasum)

    def test_request_failure_is_handled(self) -> None:
        failure = ResponseNeverReceived([Failure(defer.CancelledError())])
        with patch("cowrie.output.otx.treq.post", return_value=defer.fail(failure)):
            self.assert_resolved(self.output.submit_file(self.event(), self.sample))

        reported = self._reported()
        self.assertEqual(reported["result"], "error")
        self.assertEqual(reported["action"], "file")

    def test_multipart_wrapper_failures_are_handled(self) -> None:
        failures = (
            RequestGenerationFailed([Failure(RuntimeError("read failed"))]),
            RequestTransmissionFailed([Failure(RuntimeError("send failed"))]),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with patch(
                    "cowrie.output.otx.treq.post", return_value=defer.fail(failure)
                ):
                    self.assert_resolved(
                        self.output.submit_file(self.event(), self.sample)
                    )

        self.assertEqual(self._reported()["result"], "error")

    def test_http_error_reports_status(self) -> None:
        with patch(
            "cowrie.output.otx.treq.post",
            return_value=defer.succeed(response(500, "boom")),
        ):
            self.assert_resolved(self.output.submit_file(self.event(), self.sample))

        reported = self._reported()
        self.assertEqual(reported["result"], "error")
        self.assertEqual(reported["http_status"], 500)

    def test_upload_event_uses_attacker_filename(self) -> None:
        event = self.event(
            eventid="cowrie.session.file_upload",
            filename="dropper.sh",
            url=None,
        )
        with patch(
            "cowrie.output.otx.treq.post",
            return_value=defer.succeed(response()),
        ) as post:
            self.assert_resolved(self.output.submit_file(event, self.sample))

        self.assertEqual(post.call_args.kwargs["files"]["file"][0], "dropper.sh")

    def test_filename_is_sanitized(self) -> None:
        self.assertEqual(
            self.output._safe_filename('evil"\r\nX-Injected: yes.exe', "hash"),
            "evil___X-Injected__yes.exe",
        )
        self.assertEqual(self.output._safe_filename("", "hash"), "hash")


class OtxUrlTests(OtxTestCase):
    """post_url() submits the download URL as JSON."""

    def test_posts_url_payload(self) -> None:
        event = self.event()
        with patch(
            "cowrie.output.otx.treq.post",
            return_value=defer.succeed(response()),
        ) as post:
            self.assert_resolved(self.output.post_url(event, event["url"]))

        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["url"], SUBMIT_URL)
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
        self.assertEqual(
            json.loads(kwargs["data"].decode("utf-8")), {"url": event["url"]}
        )

        reported = self._reported()
        self.assertEqual(reported["action"], "url")
        self.assertEqual(reported["result"], "success")
        self.assertEqual(reported["url"], event["url"])


class OtxPulseTests(OtxTestCase):
    """Pulses group a day's indicators and survive restarts."""

    def test_create_pulse_with_indicators(self) -> None:
        today = datetime.datetime.now(datetime.UTC).date()
        with patch(
            "cowrie.output.otx.treq.post",
            return_value=defer.succeed(response(201, '{"id": "pulse123"}')),
        ) as post:
            self.output.report_pulse(self.event())

        kwargs = post.call_args.kwargs
        self.assertEqual(kwargs["url"], CREATE_PULSE)
        payload = json.loads(kwargs["data"].decode("utf-8"))
        self.assertEqual(
            payload["name"], f"Cowrie honeypot samples {today.isoformat()}"
        )
        self.assertTrue(payload["public"])
        self.assertEqual(payload["TLP"], "white")
        self.assertEqual(payload["tags"], ["cowrie", "honeypot"])

        types = [indicator["type"] for indicator in payload["indicators"]]
        self.assertEqual(types, ["FileHash-SHA256", "URL", "IPv4"])
        self.assertEqual(payload["indicators"][0]["indicator"], self.shasum)
        self.assertEqual(
            payload["indicators"][1]["indicator"], "http://example.com/malware.exe"
        )
        self.assertEqual(payload["indicators"][2]["indicator"], "8.8.8.8")

        self.assertEqual(self.output.pulse_id, "pulse123")
        self.assertEqual(self.output.pulse_date, today)
        with open(self.state_file, encoding="utf-8") as state:
            saved = json.load(state)
        self.assertEqual(saved, {"date": today.isoformat(), "pulse_id": "pulse123"})

        reported = self._reported()
        self.assertEqual(reported["action"], "pulse")
        self.assertEqual(reported["result"], "success")
        self.assertEqual(reported["pulse_id"], "pulse123")

    def test_second_sample_patches_existing_pulse(self) -> None:
        today = datetime.datetime.now(datetime.UTC).date()
        self.output.pulse_id = "pulse123"
        self.output.pulse_date = today

        with patch(
            "cowrie.output.otx.treq.patch",
            return_value=defer.succeed(response()),
        ) as patch_request:
            self.output.report_pulse(self.event())

        kwargs = patch_request.call_args.kwargs
        self.assertEqual(kwargs["url"], PATCH_PULSE.format("pulse123"))
        payload = json.loads(kwargs["data"].decode("utf-8"))
        self.assertEqual(
            [indicator["type"] for indicator in payload["indicators"]["add"]],
            ["FileHash-SHA256", "URL", "IPv4"],
        )

    def test_new_day_creates_a_new_pulse(self) -> None:
        yesterday = datetime.datetime.now(datetime.UTC).date() - datetime.timedelta(
            days=1
        )
        self.output.pulse_id = "old-pulse"
        self.output.pulse_date = yesterday

        with patch(
            "cowrie.output.otx.treq.post",
            return_value=defer.succeed(response(201, '{"id": "new-pulse"}')),
        ) as post:
            self.output.report_pulse(self.event())

        self.assertEqual(post.call_args.kwargs["url"], CREATE_PULSE)
        self.assertEqual(self.output.pulse_id, "new-pulse")

    def test_concurrent_samples_share_one_new_pulse(self) -> None:
        pending: defer.Deferred = defer.Deferred()
        with (
            patch("cowrie.output.otx.treq.post", return_value=pending) as post,
            patch(
                "cowrie.output.otx.treq.patch",
                return_value=defer.succeed(response()),
            ) as patch_request,
        ):
            self.output.report_pulse(self.event())
            self.output.report_pulse(self.event(shasum="b" * 64))

            # The second sample waits for the pulse the first one creates.
            post.assert_called_once()
            patch_request.assert_not_called()

            pending.callback(response(201, '{"id": "pulse123"}'))

        patch_request.assert_called_once()
        self.assertEqual(self.output.pulse_id, "pulse123")

    def test_private_source_ip_is_skipped(self) -> None:
        indicators = self.output._indicators(self.event(src_ip="10.0.0.5"))
        self.assertEqual(
            [indicator["type"] for indicator in indicators],
            ["FileHash-SHA256", "URL"],
        )

    def test_non_http_url_is_not_pulsed(self) -> None:
        indicators = self.output._indicators(
            self.event(src_ip="10.0.0.5", url="ftp://example.com/malware.exe")
        )
        self.assertEqual(
            [indicator["type"] for indicator in indicators],
            ["FileHash-SHA256"],
        )

    def test_ipv6_source_ip_is_typed(self) -> None:
        indicators = self.output._indicators(
            self.event(src_ip="2001:4860:4860::8888", url="")
        )
        self.assertEqual(
            [indicator["type"] for indicator in indicators],
            ["FileHash-SHA256", "IPv6"],
        )

    def test_deleted_pulse_is_recreated(self) -> None:
        self.output.pulse_id = "gone"
        today = datetime.datetime.now(datetime.UTC).date()
        self.output.pulse_date = today
        with open(self.state_file, "w", encoding="utf-8") as state:
            json.dump({"date": today.isoformat(), "pulse_id": "gone"}, state)

        with patch(
            "cowrie.output.otx.treq.patch",
            return_value=defer.succeed(response(404, "not found")),
        ):
            self.output.report_pulse(self.event())

        self.assertIsNone(self.output.pulse_id)
        self.assertIsNone(self.output.pulse_date)
        self.assertFalse(os.path.exists(self.state_file))
        self.assertEqual(self._reported()["result"], "error")

    def test_state_file_is_loaded_after_restart(self) -> None:
        today = datetime.datetime.now(datetime.UTC).date()
        with open(self.state_file, "w", encoding="utf-8") as state:
            json.dump({"date": today.isoformat(), "pulse_id": "pulse123"}, state)

        restarted = Output()
        restarted._state_file = Mock(return_value=self.state_file)  # type: ignore[method-assign]
        restarted._load_pulse_state()
        self.assertEqual(restarted.pulse_date, today)
        self.assertEqual(restarted.pulse_id, "pulse123")

    def test_stale_state_file_is_ignored(self) -> None:
        yesterday = datetime.datetime.now(datetime.UTC).date() - datetime.timedelta(
            days=1
        )
        with open(self.state_file, "w", encoding="utf-8") as state:
            json.dump({"date": yesterday.isoformat(), "pulse_id": "old"}, state)

        restarted = Output()
        restarted._state_file = Mock(return_value=self.state_file)  # type: ignore[method-assign]
        restarted._load_pulse_state()
        self.assertIsNone(restarted.pulse_id)


class OtxConfigTests(unittest.TestCase):
    """Configuration constraints are enforced when the plugin starts."""

    def test_red_tlp_forces_private_pulse(self) -> None:
        with patch.dict(os.environ, {"COWRIE_OUTPUT_OTX_TLP": "red"}):
            output = Output()
        self.assertFalse(output.public)
        self.assertEqual(output.tlp, "red")

    def test_invalid_group_ids_are_ignored(self) -> None:
        with patch.dict(os.environ, {"COWRIE_OUTPUT_OTX_GROUP_IDS": "1, nope, 2"}):
            output = Output()
        self.assertEqual(output.group_ids, [1, 2])


if __name__ == "__main__":
    unittest.main()
