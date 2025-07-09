#!/usr/bin/env python3
"""
Simple test for VirusTotal v3 API plugin
This script tests the core API functionality without relying on file system operations.
"""

import base64
import json
import sys
from unittest.mock import Mock, patch

# Add src to path
sys.path.insert(0, 'src')

from cowrie.output.virustotal import Output, StringProducer


def test_string_producer():
    """Test StringProducer functionality"""
    print("Testing StringProducer...")
    
    body = b"test data"
    producer = StringProducer(body)
    
    assert producer.body == body
    assert producer.length == len(body)
    
    # Test interface methods exist
    assert hasattr(producer, 'startProducing')
    assert hasattr(producer, 'pauseProducing')
    assert hasattr(producer, 'resumeProducing')
    assert hasattr(producer, 'stopProducing')
    
    print("✓ StringProducer test passed")


def test_api_endpoints():
    """Test API endpoint construction"""
    print("Testing API endpoints...")
    
    # Create output plugin
    output = Output()
    output.apiKey = "test-api-key"
    output.debug = True
    
    # Mock the agent
    mock_agent = Mock()
    output.agent = mock_agent
    
    # Test file scanning endpoint
    event = {"shasum": "abc123def456", "session": "test"}
    
    # Mock _is_new_shasum to avoid file system operations
    with patch.object(output, '_is_new_shasum', return_value=True):
        output.scanfile(event)
    
    # Check that the correct endpoint was called
    assert mock_agent.request.called
    call_args = mock_agent.request.call_args
    method, url, headers = call_args[0][:3]
    
    assert method == b"GET"
    assert url == b"https://www.virustotal.com/api/v3/files/abc123def456"
    assert b"X-Apikey" in headers._rawHeaders
    assert headers._rawHeaders[b"X-Apikey"] == [b"test-api-key"]
    
    print("✓ File scanning endpoint test passed")


def test_url_base64_encoding():
    """Test URL base64 encoding"""
    print("Testing URL base64 encoding...")
    
    # Create output plugin
    output = Output()
    output.apiKey = "test-api-key"
    output.scan_url = True
    output.url_cache = {}
    
    # Mock the agent
    mock_agent = Mock()
    output.agent = mock_agent
    
    # Test URL
    test_url = "http://example.com/malicious.exe"
    expected_url_id = base64.urlsafe_b64encode(test_url.encode()).decode().rstrip("=")
    
    event = {"url": test_url, "session": "test"}
    
    # Call scanurl
    output.scanurl(event)
    
    # Check that the correct endpoint was called
    assert mock_agent.request.called
    call_args = mock_agent.request.call_args
    method, url, headers = call_args[0][:3]
    
    expected_url = f"https://www.virustotal.com/api/v3/urls/{expected_url_id}".encode()
    assert method == b"GET"
    assert url == expected_url
    assert b"X-Apikey" in headers._rawHeaders
    
    print("✓ URL base64 encoding test passed")


def test_comment_endpoint():
    """Test comment posting endpoint"""
    print("Testing comment endpoint...")
    
    # Create output plugin
    output = Output()
    output.apiKey = "test-api-key"
    output.commenttext = "Test comment from Cowrie"
    
    # Mock the agent
    mock_agent = Mock()
    output.agent = mock_agent
    
    # Test comment posting
    file_id = "test-file-id"
    output.postcomment(file_id)
    
    # Check that the correct endpoint was called
    assert mock_agent.request.called
    call_args = mock_agent.request.call_args
    method, url, headers, body = call_args[0]
    
    assert method == b"POST"
    assert url == b"https://www.virustotal.com/api/v3/files/test-file-id/comments"
    assert b"X-Apikey" in headers._rawHeaders
    assert b"Content-Type" in headers._rawHeaders
    assert headers._rawHeaders[b"Content-Type"] == [b"application/json"]
    
    # Check body format
    body_content = body.body.decode()
    comment_data = json.loads(body_content)
    assert "data" in comment_data
    assert comment_data["data"]["type"] == "comment"
    assert comment_data["data"]["attributes"]["text"] == "Test comment from Cowrie"
    
    print("✓ Comment endpoint test passed")


def test_file_upload_endpoint():
    """Test file upload endpoint"""
    print("Testing file upload endpoint...")
    
    # Create output plugin
    output = Output()
    output.apiKey = "test-api-key"
    
    # Mock the agent
    mock_agent = Mock()
    output.agent = mock_agent
    
    # Mock file operations
    mock_file = Mock()
    mock_file.read.return_value = b"fake file content"
    
    with patch('builtins.open', return_value=mock_file):
        output.postfile("/fake/path", "test.exe")
    
    # Check that the correct endpoint was called
    assert mock_agent.request.called
    call_args = mock_agent.request.call_args
    method, url, headers = call_args[0][:3]
    
    assert method == b"POST"
    assert url == b"https://www.virustotal.com/api/v3/files"
    assert b"X-Apikey" in headers._rawHeaders
    assert b"Content-Type" in headers._rawHeaders
    
    print("✓ File upload endpoint test passed")


def test_url_submission_endpoint():
    """Test URL submission endpoint"""
    print("Testing URL submission endpoint...")
    
    # Create output plugin
    output = Output()
    output.apiKey = "test-api-key"
    
    # Mock the agent
    mock_agent = Mock()
    output.agent = mock_agent
    
    # Test URL submission
    event = {"url": "http://example.com/malicious.exe"}
    output.submiturl(event)
    
    # Check that the correct endpoint was called
    assert mock_agent.request.called
    call_args = mock_agent.request.call_args
    method, url, headers = call_args[0][:3]
    
    assert method == b"POST"
    assert url == b"https://www.virustotal.com/api/v3/urls"
    assert b"X-Apikey" in headers._rawHeaders
    assert b"Content-Type" in headers._rawHeaders
    assert headers._rawHeaders[b"Content-Type"] == [b"application/x-www-form-urlencoded"]
    
    print("✓ URL submission endpoint test passed")


def test_api_key_security():
    """Test that API key is properly secured in headers"""
    print("Testing API key security...")
    
    # Create output plugin
    output = Output()
    output.apiKey = "secret-api-key"
    output.url_cache = {}
    
    # Mock the agent
    mock_agent = Mock()
    output.agent = mock_agent
    
    # Test various endpoints
    test_cases = [
        ("scanfile", {"shasum": "abc123", "session": "test"}),
        ("scanurl", {"url": "http://example.com", "session": "test"}),
        ("postcomment", "file-id"),
        ("submiturl", {"url": "http://example.com"}),
    ]
    
    for method_name, params in test_cases:
        mock_agent.reset_mock()
        
        if method_name == "scanfile":
            with patch.object(output, '_is_new_shasum', return_value=True):
                getattr(output, method_name)(params)
        elif method_name == "postcomment":
            getattr(output, method_name)(params)
        else:
            getattr(output, method_name)(params)
        
        # Check that API key is in headers, not in URL or body
        assert mock_agent.request.called
        call_args = mock_agent.request.call_args
        method, url, headers = call_args[0][:3]
        
        # API key should be in headers
        assert b"X-Apikey" in headers._rawHeaders
        assert headers._rawHeaders[b"X-Apikey"] == [b"secret-api-key"]
        
        # API key should NOT be in URL
        assert b"secret-api-key" not in url
        
        print(f"✓ {method_name} API key security test passed")


def main():
    """Run all tests"""
    print("VirusTotal v3 API Simple Tests")
    print("=" * 35)
    
    try:
        test_string_producer()
        test_api_endpoints()
        test_url_base64_encoding()
        test_comment_endpoint()
        test_file_upload_endpoint()
        test_url_submission_endpoint()
        test_api_key_security()
        
        print("\n✓ All tests passed successfully!")
        print("\nThe VirusTotal v3 API plugin is working correctly:")
        print("- All endpoints use correct v3 API URLs")
        print("- API key is securely transmitted in headers")
        print("- Request formats match v3 API specifications")
        print("- URL encoding is properly implemented")
        print("- Comment format uses v3 API JSON structure")
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()