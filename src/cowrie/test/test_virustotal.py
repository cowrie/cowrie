# SPDX-FileCopyrightText: 2025 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from twisted.internet import defer

from cowrie.output import virustotal
from cowrie.output.virustotal import Output


class VirusTotalOutputTests(unittest.TestCase):
    """Test suite for VirusTotal v3 API output plugin"""

    def setUp(self) -> None:
        """Set up test environment"""
        self.output = Output()

        # Mock agent
        self.output.agent = Mock()
        self.output.apiKey = "test-api-key"
        self.output.debug = True
        self.output.upload = True
        self.output.comment = True
        self.output.scan_file = True
        self.output.scan_url = True
        self.output.commenttext = "Test comment"
        self.output.url_cache = {}

    def test_scanfile_new_file_not_found(self) -> None:
        """Test file scanning when file is not found in VirusTotal database"""
        # Mock agent request
        deferred: defer.Deferred = defer.Deferred()
        self.output.agent.request.return_value = deferred

        # Mock file upload
        self.output.postfile = Mock(return_value=defer.succeed(None))  # type: ignore

        # Test event
        event = {
            "session": "test-session",
            "shasum": "abc123",
            "outfile": "/tmp/test-file",
            "url": "http://example.com/file.bin",
        }

        # Call scanfile
        self.output.scanfile(event)

        # Verify request was made with correct parameters
        self.output.agent.request.assert_called_once()
        call_args = self.output.agent.request.call_args

        # Check method and URL
        self.assertEqual(call_args[0][0], b"GET")
        self.assertEqual(
            call_args[0][1], b"https://www.virustotal.com/api/v3/files/abc123"
        )

        # Check headers (header names are normalized)
        headers = call_args[0][2]
        self.assertIn(b"X-Apikey", headers._rawHeaders)
        self.assertEqual(headers._rawHeaders[b"X-Apikey"], [b"test-api-key"])

    def test_scanurl_base64_encoding(self) -> None:
        """Test URL scanning with base64 encoding"""
        test_url = "http://example.com/malicious.exe"
        expected_url_id = (
            base64.urlsafe_b64encode(test_url.encode()).decode().rstrip("=")
        )

        # Mock agent request
        deferred: defer.Deferred = defer.Deferred()
        self.output.agent.request.return_value = deferred

        # Mock URL submission
        self.output.submiturl = Mock(return_value=defer.succeed(None))  # type: ignore

        # Test event
        event = {"session": "test-session", "url": test_url}

        # Call scanurl
        self.output.scanurl(event)

        # Verify request was made with correct base64 encoded URL
        self.output.agent.request.assert_called_once()
        call_args = self.output.agent.request.call_args
        expected_url = (
            f"https://www.virustotal.com/api/v3/urls/{expected_url_id}".encode()
        )
        self.assertEqual(call_args[0][1], expected_url)

    def test_postfile_v3_format(self) -> None:
        """Test file upload using v3 API format"""
        # Create a temporary file for testing
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test file content")
            tmp_path = tmp.name

        try:
            # Mock agent request
            deferred: defer.Deferred = defer.Deferred()
            self.output.agent.request.return_value = deferred

            # Mock comment posting
            self.output.postcomment = Mock(return_value=defer.succeed(True))  # type: ignore

            # Call postfile
            self.output.postfile(tmp_path, "test-file.exe", "abc123sha256")

            # Verify request was made correctly
            self.output.agent.request.assert_called_once()
            call_args = self.output.agent.request.call_args

            # Check method and URL
            self.assertEqual(call_args[0][0], b"POST")
            self.assertEqual(
                call_args[0][1], b"https://www.virustotal.com/api/v3/files"
            )

            # Check headers include x-apikey
            headers = call_args[0][2]
            self.assertIn(b"X-Apikey", headers._rawHeaders)
            self.assertEqual(headers._rawHeaders[b"X-Apikey"], [b"test-api-key"])

        finally:
            # Clean up temporary file
            os.unlink(tmp_path)

    def test_upload_comments_and_collects_by_file_hash(self) -> None:
        """A fresh upload must comment on and add to the collection by the
        file's sha256, not the analysis id the upload returns."""
        self.output.comment = True
        self.output.commenttext = "Test comment"
        self.output.collection_id = "test-collection-id"

        captured: dict = {}

        def fake_make_request(*args, **kwargs):
            captured["process_response"] = kwargs.get("process_response")
            return defer.succeed(None)

        self.output._make_request = fake_make_request  # type: ignore[method-assign]
        self.output._post_comment = Mock(return_value=defer.succeed(True))  # type: ignore[method-assign]
        self.output._add_to_collection = Mock(return_value=defer.succeed(True))  # type: ignore[method-assign]

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"payload")
            tmp_path = tmp.name
        try:
            self.output.postfile(tmp_path, "payload.exe", "HASH256")
            # The v3 upload response carries an analysis id, not the file hash.
            captured["process_response"](
                json.dumps(
                    {"data": {"id": "analysis-xyz", "type": "analysis"}}
                ).encode()
            )
        finally:
            os.unlink(tmp_path)

        self.output._post_comment.assert_called_once_with("files", "HASH256", "Comment")
        self.output._add_to_collection.assert_called_once()
        self.assertEqual(self.output._add_to_collection.call_args[0][1], "HASH256")

    def test_postcomment_v3_format(self) -> None:
        """Test comment posting using v3 API format"""
        # Mock agent request
        deferred: defer.Deferred = defer.Deferred()
        self.output.agent.request.return_value = deferred

        # Call postcomment
        self.output.postcomment("test-file-id")

        # Verify request was made correctly
        self.output.agent.request.assert_called_once()
        call_args = self.output.agent.request.call_args

        # Check method and URL
        self.assertEqual(call_args[0][0], b"POST")
        self.assertEqual(
            call_args[0][1],
            b"https://www.virustotal.com/api/v3/files/test-file-id/comments",
        )

        # Check headers
        headers = call_args[0][2]
        self.assertIn(b"X-Apikey", headers._rawHeaders)
        self.assertIn(b"Content-Type", headers._rawHeaders)
        self.assertEqual(headers._rawHeaders[b"Content-Type"], [b"application/json"])

    def test_postcomment_url_v3_format(self) -> None:
        """Test URL comment posting using v3 API format"""
        # Mock agent request
        deferred: defer.Deferred = defer.Deferred()
        self.output.agent.request.return_value = deferred

        # Call postcomment_url
        self.output.postcomment_url("test-url-id")

        # Verify request was made correctly
        self.output.agent.request.assert_called_once()
        call_args = self.output.agent.request.call_args

        # Check method and URL
        self.assertEqual(call_args[0][0], b"POST")
        self.assertEqual(
            call_args[0][1],
            b"https://www.virustotal.com/api/v3/urls/test-url-id/comments",
        )

        # Check headers
        headers = call_args[0][2]
        self.assertIn(b"X-Apikey", headers._rawHeaders)
        self.assertIn(b"Content-Type", headers._rawHeaders)
        self.assertEqual(headers._rawHeaders[b"Content-Type"], [b"application/json"])

    def test_submiturl_v3_format(self) -> None:
        """Test URL submission using v3 API format"""
        # Mock agent request
        deferred: defer.Deferred = defer.Deferred()
        self.output.agent.request.return_value = deferred

        # Test event
        event = {"url": "http://example.com/malicious.exe"}

        # Call submiturl
        self.output.submiturl(event)

        # Verify request was made correctly
        self.output.agent.request.assert_called_once()
        call_args = self.output.agent.request.call_args

        # Check method and URL
        self.assertEqual(call_args[0][0], b"POST")
        self.assertEqual(call_args[0][1], b"https://www.virustotal.com/api/v3/urls")

        # Check headers
        headers = call_args[0][2]
        self.assertIn(b"X-Apikey", headers._rawHeaders)
        self.assertIn(b"Content-Type", headers._rawHeaders)
        self.assertEqual(
            headers._rawHeaders[b"Content-Type"], [b"application/x-www-form-urlencoded"]
        )

    def test_url_cache_functionality(self) -> None:
        """Test URL caching functionality"""
        test_url = "http://example.com/cached.exe"

        # Add URL to cache
        import datetime

        self.output.url_cache[test_url] = datetime.datetime.now()

        # Test event
        event = {"url": test_url}

        # Call scanurl - should return early due to cache
        self.output.scanurl(event)

        # Verify no request was made
        self.output.agent.request.assert_not_called()

    def test_write_method_file_download(self) -> None:
        """Test write method for file download events"""
        # Mock methods
        self.output.scanfile = Mock()  # type: ignore
        self.output.scanurl = Mock()  # type: ignore
        self.output._is_new_shasum = Mock(return_value=True)  # type: ignore

        # Test file download event
        event = {
            "eventid": "cowrie.session.file_download",
            "shasum": "abc123",
            "url": "http://example.com/file.exe",
        }

        # Call write
        self.output.write(event)

        # Verify both scanfile and scanurl were called
        self.output.scanfile.assert_called_once_with(event)
        self.output.scanurl.assert_called_once_with(event)

    def test_write_method_file_upload(self) -> None:
        """Test write method for file upload events"""
        # Mock methods
        self.output.scanfile = Mock()  # type: ignore
        self.output._is_new_shasum = Mock(return_value=True)  # type: ignore

        # Test file upload event
        event = {"eventid": "cowrie.session.file_upload", "shasum": "def456"}

        # Call write
        self.output.write(event)

        # Verify scanfile was called
        self.output.scanfile.assert_called_once_with(event)

    def test_api_key_in_headers(self) -> None:
        """Test that API key is correctly placed in headers for all requests"""
        methods_to_test = [
            ("scanfile", {"session": "test", "shasum": "abc123"}),
            ("scanurl", {"session": "test", "url": "http://example.com"}),
            ("postcomment", "test-file-id"),
            ("postcomment_url", "test-url-id"),
            ("submiturl", {"url": "http://example.com"}),
        ]

        for method_name, params in methods_to_test:
            with self.subTest(method=method_name):
                # Mock agent request
                deferred: defer.Deferred = defer.Deferred()
                self.output.agent.request.return_value = deferred

                # Call method
                method = getattr(self.output, method_name)
                if method_name in ("postcomment", "postcomment_url"):
                    method(params)
                else:
                    method(params)

                # Verify x-apikey header is present
                call_args = self.output.agent.request.call_args
                headers = call_args[0][2]
                self.assertIn(b"X-Apikey", headers._rawHeaders)
                self.assertEqual(headers._rawHeaders[b"X-Apikey"], [b"test-api-key"])

                # Reset mock for next test
                self.output.agent.request.reset_mock()

    def _started(self, config: Mock) -> Output:
        """Construct the plugin and run start() against the given config."""
        with patch.object(virustotal.Output, "start", lambda self: None):
            output = virustotal.Output()
        with patch.object(virustotal, "CowrieConfig", config):
            output.start()
        return output

    def test_start_reads_collection_id_from_config(self) -> None:
        """start() must load collection_id from config and create nothing."""
        config = Mock()
        config.get.side_effect = lambda section, option, fallback=None: {
            "collection_id": "EXISTING-ID",
        }.get(option, fallback)
        config.getboolean.side_effect = lambda section, option, fallback=False: fallback

        output = self._started(config)

        self.assertEqual(output.collection_id, "EXISTING-ID")

    def test_start_warns_when_deprecated_collection_set(self) -> None:
        """A configured 'collection' is ignored and must emit a warning."""
        log = Mock()
        config = Mock()
        config.get.side_effect = lambda section, option, fallback=None: {
            "collection": "cowrie",
        }.get(option, fallback)
        config.getboolean.side_effect = lambda section, option, fallback=False: fallback

        with patch.object(virustotal.Output, "_log", log):
            self._started(config)

        log.warn.assert_called_once()

    def test_add_file_to_collection(self) -> None:
        """Test adding a file to a collection"""
        # Setup output with collection
        self.output.collection_id = "test-collection-id"

        # Mock agent request
        deferred: defer.Deferred = defer.Deferred()
        self.output.agent.request.return_value = deferred

        # Add file to collection
        self.output._add_to_collection("files", "test-file-hash", "test file")

        # Verify request was made
        self.assertTrue(self.output.agent.request.called)
        call_args = self.output.agent.request.call_args
        method, url, _headers, body = call_args[0]

        # Check method and URL
        self.assertEqual(method, b"POST")
        self.assertEqual(
            url,
            b"https://www.virustotal.com/api/v3/collections/test-collection-id/files",
        )

        # Check body format
        body_content = body.body.decode()
        data = json.loads(body_content)
        self.assertEqual(data["data"][0]["type"], "file")
        self.assertEqual(data["data"][0]["id"], "test-file-hash")

    def test_add_url_to_collection(self) -> None:
        """Test adding a URL to a collection"""
        # Setup output with collection
        self.output.collection_id = "test-collection-id"

        # Mock agent request
        deferred: defer.Deferred = defer.Deferred()
        self.output.agent.request.return_value = deferred

        # Add URL to collection
        self.output._add_to_collection("urls", "test-url-id", "test URL")

        # Verify request was made
        self.assertTrue(self.output.agent.request.called)
        call_args = self.output.agent.request.call_args
        method, url, _headers, body = call_args[0]

        # Check method and URL
        self.assertEqual(method, b"POST")
        self.assertEqual(
            url,
            b"https://www.virustotal.com/api/v3/collections/test-collection-id/urls",
        )

        # Check body format
        body_content = body.body.decode()
        data = json.loads(body_content)
        self.assertEqual(data["data"][0]["type"], "url")
        self.assertEqual(data["data"][0]["id"], "test-url-id")

    def test_no_collection_when_not_configured(self) -> None:
        """Test that collection operations are skipped when not configured"""
        # Ensure no collection is configured
        self.output.collection_id = None

        # Mock agent request
        self.output.agent.request.reset_mock()

        # Try to add to collection
        self.output._add_to_collection("files", "test-file", "test file")

        # Verify no request was made
        self.assertFalse(self.output.agent.request.called)


if __name__ == "__main__":
    unittest.main()
