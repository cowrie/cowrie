# Copyright (c) 2025 Michel Oosterhof
# See LICENSE for details.
from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from unittest.mock import Mock

from twisted.internet import defer

from cowrie.output.virustotal import Output, StringProducer


class MockResponse:
    """Mock HTTP response for testing"""

    def __init__(self, code: int, data: bytes):
        self.code = code
        self.data = data


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

    def test_string_producer_interface(self) -> None:
        """Test StringProducer implements required interface methods"""
        body = b"test data"
        producer = StringProducer(body)

        self.assertEqual(producer.body, body)
        self.assertEqual(producer.length, len(body))

        # Test all interface methods exist
        self.assertTrue(hasattr(producer, "startProducing"))
        self.assertTrue(hasattr(producer, "pauseProducing"))
        self.assertTrue(hasattr(producer, "resumeProducing"))
        self.assertTrue(hasattr(producer, "stopProducing"))

    def test_scanfile_new_file_not_found(self) -> None:
        """Test file scanning when file is not found in VirusTotal database"""
        # Mock response for file not found
        MockResponse(
            200,
            json.dumps(
                {"error": {"code": "NotFoundError", "message": "File not found"}}
            ).encode(),
        )

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

    def test_scanfile_existing_file_found(self) -> None:
        """Test file scanning when file exists in VirusTotal database"""
        # Mock response for existing file
        MockResponse(
            200,
            json.dumps(
                {
                    "data": {
                        "id": "abc123",
                        "attributes": {
                            "last_analysis_results": {
                                "Avast": {
                                    "category": "malicious",
                                    "result": "Trojan.Test",
                                },
                                "Kaspersky": {"category": "clean", "result": "Clean"},
                            },
                            "last_analysis_stats": {
                                "malicious": 1,
                                "clean": 1,
                                "suspicious": 0,
                                "undetected": 0,
                            },
                            "last_analysis_date": "2025-01-10T10:00:00Z",
                        },
                    }
                }
            ).encode(),
        )

        # Mock agent request
        deferred: defer.Deferred = defer.Deferred()
        self.output.agent.request.return_value = deferred

        # Test event
        event = {"session": "test-session", "shasum": "abc123"}

        # Call scanfile
        self.output.scanfile(event)

        # Verify request was made correctly
        self.output.agent.request.assert_called_once()
        call_args = self.output.agent.request.call_args
        self.assertEqual(call_args[0][0], b"GET")
        self.assertEqual(
            call_args[0][1], b"https://www.virustotal.com/api/v3/files/abc123"
        )

    def test_scanurl_base64_encoding(self) -> None:
        """Test URL scanning with base64 encoding"""
        test_url = "http://example.com/malicious.exe"
        expected_url_id = (
            base64.urlsafe_b64encode(test_url.encode()).decode().rstrip("=")
        )

        # Mock response for URL not found
        MockResponse(
            200,
            json.dumps(
                {"error": {"code": "NotFoundError", "message": "URL not found"}}
            ).encode(),
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
            # Mock response for successful upload
            MockResponse(
                200,
                json.dumps(
                    {"data": {"id": "uploaded-file-id", "type": "analysis"}}
                ).encode(),
            )

            # Mock agent request
            deferred: defer.Deferred = defer.Deferred()
            self.output.agent.request.return_value = deferred

            # Mock comment posting
            self.output.postcomment = Mock(return_value=defer.succeed(True))  # type: ignore

            # Call postfile
            self.output.postfile(tmp_path, "test-file.exe")

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

    def test_postcomment_v3_format(self) -> None:
        """Test comment posting using v3 API format"""
        # Mock response for successful comment
        MockResponse(
            200, json.dumps({"data": {"id": "comment-id", "type": "comment"}}).encode()
        )

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
        # Mock response for successful URL comment
        MockResponse(
            200, json.dumps({"data": {"id": "comment-id", "type": "comment"}}).encode()
        )

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
        # Mock response for successful URL submission
        MockResponse(200, b"")

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

    def test_collection_initialization(self) -> None:
        """Test collection initialization"""
        # Create output plugin with collection configured
        output = Output()
        output.apiKey = "test-api-key"
        output.debug = True
        output.collection_name = "test-collection"

        # Mock agent
        mock_agent = Mock()
        output.agent = mock_agent

        # Initialize collection
        output._init_collection()

        # Verify request was made
        self.assertTrue(mock_agent.request.called)
        call_args = mock_agent.request.call_args
        method, url, _headers, body = call_args[0]

        # Check method and URL
        self.assertEqual(method, b"POST")
        self.assertEqual(url, b"https://www.virustotal.com/api/v3/collections")

        # Check body format
        body_content = body.body.decode()
        collection_data = json.loads(body_content)
        self.assertEqual(collection_data["data"]["type"], "collection")
        self.assertEqual(
            collection_data["data"]["attributes"]["name"], "test-collection"
        )

    def test_add_file_to_collection(self) -> None:
        """Test adding a file to a collection"""
        # Setup output with collection
        self.output.collection_name = "test-collection"
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
            url, b"https://www.virustotal.com/api/v3/collections/test-collection-id/files"
        )

        # Check body format
        body_content = body.body.decode()
        data = json.loads(body_content)
        self.assertEqual(data["data"][0]["type"], "file")
        self.assertEqual(data["data"][0]["id"], "test-file-hash")

    def test_add_url_to_collection(self) -> None:
        """Test adding a URL to a collection"""
        # Setup output with collection
        self.output.collection_name = "test-collection"
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
            url, b"https://www.virustotal.com/api/v3/collections/test-collection-id/urls"
        )

        # Check body format
        body_content = body.body.decode()
        data = json.loads(body_content)
        self.assertEqual(data["data"][0]["type"], "url")
        self.assertEqual(data["data"][0]["id"], "test-url-id")

    def test_no_collection_when_not_configured(self) -> None:
        """Test that collection operations are skipped when not configured"""
        # Ensure no collection is configured
        self.output.collection_name = None
        self.output.collection_id = None

        # Mock agent request
        self.output.agent.request.reset_mock()

        # Try to add to collection
        self.output._add_to_collection("files", "test-file", "test file")

        # Verify no request was made
        self.assertFalse(self.output.agent.request.called)


if __name__ == "__main__":
    unittest.main()
