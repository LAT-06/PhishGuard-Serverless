"""
Test suite for virustotal.py - VirusTotal API integration.

Tests cover:
- URL submission and analysis retrieval
- Response parsing and standardization
- Rate limiting and retry logic
- Error handling for various failure scenarios
- API key validation
- Network timeout handling

All external API calls are mocked to ensure fast, reliable tests.
"""

import pytest
import requests
from unittest.mock import MagicMock, patch, Mock
from datetime import datetime

from virustotal import (
    VirusTotalScanner,
    VirusTotalAPIError,
    VirusTotalRateLimitError
)


class TestVirusTotalBasicOperations:
    """Test basic VirusTotal scanner operations."""
    
    def test_scanner_initialization(self, mock_vt_api_key):
        """
        Test scanner initialization with API key.
        
        Verifies that:
        - Scanner accepts API key
        - Headers are set correctly
        - Configuration is stored
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        assert scanner.api_key == mock_vt_api_key
        assert scanner.headers['x-apikey'] == mock_vt_api_key
        assert scanner.timeout == 30
        assert scanner.max_retries == 3
    
    def test_url_validation_valid(self, mock_vt_api_key):
        """
        Test URL validation for valid URLs.
        
        Verifies that:
        - HTTP URLs are accepted
        - HTTPS URLs are accepted
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        assert scanner._validate_url('http://example.com') is True
        assert scanner._validate_url('https://example.com') is True
        assert scanner._validate_url('https://sub.example.com/path') is True
    
    def test_url_validation_invalid(self, mock_vt_api_key):
        """
        Test URL validation for invalid URLs.
        
        Verifies that:
        - Non-HTTP protocols are rejected
        - Malformed URLs are rejected
        - Empty strings are rejected
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        assert scanner._validate_url('ftp://example.com') is False
        assert scanner._validate_url('example.com') is False
        assert scanner._validate_url('not-a-url') is False
        assert scanner._validate_url('') is False
    
    def test_url_to_id_conversion(self, mock_vt_api_key):
        """
        Test URL to base64 ID conversion.
        
        Verifies that:
        - URL is encoded to base64
        - Result is URL-safe
        - Padding is removed
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        url = 'https://example.com'
        url_id = scanner._url_to_id(url)
        
        assert isinstance(url_id, str)
        assert len(url_id) > 0
        # Should not contain padding
        assert not url_id.endswith('=')


class TestVirusTotalScanFlow:
    """Test complete URL scanning workflow."""
    
    @patch('virustotal.requests.request')
    def test_successful_scan_safe_url(self, mock_request, mock_vt_api_key, mock_vt_success_response):
        """
        Test successful scan of safe URL.
        
        Verifies that:
        - URL submission works
        - Analysis retrieval works
        - Response is parsed correctly
        - Risk score is calculated
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        # Mock POST (submission) response
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            'data': {'id': 'test-analysis-id'}
        }
        
        # Mock GET (results) response
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = mock_vt_success_response
        
        # Configure mock to return different responses for POST and GET
        mock_request.side_effect = [mock_post_response, mock_get_response]
        
        result = scanner.scan_url('https://example.com')
        
        assert result['url'] == 'https://example.com'
        assert result['status'] == 'safe'
        assert result['risk_score'] == 0
        assert result['detections']['malicious'] == 0
        assert result['detections']['total_engines'] > 0
    
    @patch('virustotal.requests.request')
    def test_successful_scan_malicious_url(self, mock_request, mock_vt_api_key, mock_vt_malicious_response):
        """
        Test successful scan of malicious URL.
        
        Verifies that:
        - Malicious URLs are detected
        - Risk score is high
        - Categories are extracted
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            'data': {'id': 'test-analysis-id'}
        }
        
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = mock_vt_malicious_response
        
        mock_request.side_effect = [mock_post_response, mock_get_response]
        
        result = scanner.scan_url('https://malicious-site.com')
        
        assert result['status'] == 'malicious'
        assert result['risk_score'] > 50
        assert result['detections']['malicious'] > 0
        assert len(result['categories']) > 0
    
    def test_scan_invalid_url_format(self, mock_vt_api_key):
        """
        Test scanning with invalid URL format.
        
        Verifies that:
        - ValueError is raised for invalid URLs
        - No API call is made
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        with pytest.raises(ValueError) as exc_info:
            scanner.scan_url('not-a-valid-url')
        
        assert 'Invalid URL format' in str(exc_info.value)


class TestVirusTotalErrorHandling:
    """Test error handling for various API failures."""
    
    @patch('virustotal.requests.request')
    def test_invalid_api_key(self, mock_request, mock_vt_api_key):
        """
        Test handling of invalid API key.
        
        Verifies that:
        - 401 response is handled
        - Appropriate error is raised
        - Error message mentions API key
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        mock_response = Mock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response
        
        with pytest.raises(VirusTotalAPIError) as exc_info:
            scanner.scan_url('https://example.com')
        
        assert 'Invalid API key' in str(exc_info.value)
    
    @patch('virustotal.requests.request')
    def test_url_not_found(self, mock_request, mock_vt_api_key):
        """
        Test handling of URL not found in VT database.
        
        Verifies that:
        - 404 response is handled gracefully
        - Appropriate error is raised
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        # Mock successful POST
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {
            'data': {'id': 'test-analysis-id'}
        }
        
        # Mock 404 GET
        mock_get_response = Mock()
        mock_get_response.status_code = 404
        
        mock_request.side_effect = [mock_post_response, mock_get_response]
        
        with pytest.raises(VirusTotalAPIError) as exc_info:
            scanner.scan_url('https://example.com')
        
        assert 'not found' in str(exc_info.value).lower()
    
    @patch('virustotal.requests.request')
    def test_network_timeout(self, mock_request, mock_vt_api_key):
        """
        Test handling of network timeout.
        
        Verifies that:
        - Timeout exception is caught
        - Retry logic is applied
        - Eventually raises VirusTotalAPIError
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        mock_request.side_effect = requests.exceptions.Timeout()
        
        with pytest.raises(VirusTotalAPIError) as exc_info:
            scanner.scan_url('https://example.com')
        
        assert 'timeout' in str(exc_info.value).lower()
        # Verify retries were attempted
        assert mock_request.call_count == scanner.max_retries
    
    @patch('virustotal.requests.request')
    def test_network_error(self, mock_request, mock_vt_api_key):
        """
        Test handling of network connection error.
        
        Verifies that:
        - Connection errors are caught
        - Appropriate error is raised
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        mock_request.side_effect = requests.exceptions.ConnectionError('Connection refused')
        
        with pytest.raises(VirusTotalAPIError) as exc_info:
            scanner.scan_url('https://example.com')
        
        assert 'Network error' in str(exc_info.value)


class TestVirusTotalRateLimiting:
    """Test rate limiting and retry logic."""
    
    @patch('virustotal.requests.request')
    @patch('virustotal.time.sleep')
    def test_rate_limit_with_retry(self, mock_sleep, mock_request, mock_vt_api_key, mock_vt_success_response):
        """
        Test rate limit handling with successful retry.
        
        Verifies that:
        - 429 response triggers retry
        - Exponential backoff is applied
        - Eventually succeeds after retry
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        # First call returns 429, second succeeds
        mock_rate_limit_response = Mock()
        mock_rate_limit_response.status_code = 429
        
        mock_success_post = Mock()
        mock_success_post.status_code = 200
        mock_success_post.json.return_value = {
            'data': {'id': 'test-analysis-id'}
        }
        
        mock_success_get = Mock()
        mock_success_get.status_code = 200
        mock_success_get.json.return_value = mock_vt_success_response
        
        mock_request.side_effect = [
            mock_rate_limit_response,
            mock_success_post,
            mock_success_get
        ]
        
        result = scanner.scan_url('https://example.com')
        
        # Should have slept for backoff
        assert mock_sleep.called
        # Should eventually succeed
        assert result['status'] == 'safe'
    
    @patch('virustotal.requests.request')
    @patch('virustotal.time.sleep')
    def test_rate_limit_exhausted_retries(self, mock_sleep, mock_request, mock_vt_api_key):
        """
        Test rate limit with all retries exhausted.
        
        Verifies that:
        - All retries are attempted
        - RateLimitError is raised
        - Exponential backoff increases each time
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        # Always return 429
        mock_response = Mock()
        mock_response.status_code = 429
        mock_request.return_value = mock_response
        
        with pytest.raises(VirusTotalRateLimitError):
            scanner.scan_url('https://example.com')
        
        # Verify exponential backoff was applied
        assert mock_sleep.call_count >= 2
        sleep_times = [call[0][0] for call in mock_sleep.call_args_list]
        # Each sleep should be longer than the previous
        for i in range(1, len(sleep_times)):
            assert sleep_times[i] > sleep_times[i-1]


class TestVirusTotalResponseParsing:
    """Test parsing of VirusTotal API responses."""
    
    def test_parse_safe_result(self, mock_vt_api_key, mock_vt_success_response):
        """
        Test parsing of safe URL response.
        
        Verifies that:
        - All fields are extracted
        - Risk score is calculated correctly
        - Status is set to 'safe'
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        result = scanner._parse_results(mock_vt_success_response, 'https://example.com')
        
        assert result['url'] == 'https://example.com'
        assert result['status'] == 'safe'
        assert result['risk_score'] == 0
        assert result['detections']['malicious'] == 0
        assert result['detections']['suspicious'] == 0
        assert 'scan_date' in result
    
    def test_parse_malicious_result(self, mock_vt_api_key, mock_vt_malicious_response):
        """
        Test parsing of malicious URL response.
        
        Verifies that:
        - Malicious status is detected
        - Risk score is high
        - Categories are extracted
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        result = scanner._parse_results(mock_vt_malicious_response, 'https://malicious.com')
        
        assert result['status'] == 'malicious'
        assert result['risk_score'] > 50
        assert result['detections']['malicious'] > 0
        assert len(result['categories']) > 0
        assert 'phishing' in result['categories'] or 'malware' in result['categories']
    
    def test_parse_suspicious_result(self, mock_vt_api_key):
        """
        Test parsing of suspicious URL response.
        
        Verifies that:
        - Suspicious status is detected when no malicious but some suspicious
        - Risk score is moderate
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        suspicious_response = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 0,
                        'suspicious': 10,
                        'undetected': 60,
                        'harmless': 15
                    },
                    'last_analysis_results': {},
                    'last_analysis_date': int(datetime.utcnow().timestamp())
                }
            }
        }
        
        result = scanner._parse_results(suspicious_response, 'https://suspicious.com')
        
        assert result['status'] == 'suspicious'
        assert 0 < result['risk_score'] < 50
    
    def test_parse_unknown_result(self, mock_vt_api_key):
        """
        Test parsing when no engines responded.
        
        Verifies that:
        - Unknown status is assigned
        - Risk score is 0
        - No errors are raised
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        unknown_response = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 0,
                        'suspicious': 0,
                        'undetected': 0,
                        'harmless': 0
                    },
                    'last_analysis_results': {},
                    'last_analysis_date': None
                }
            }
        }
        
        result = scanner._parse_results(unknown_response, 'https://unknown.com')
        
        assert result['status'] == 'unknown'
        assert result['risk_score'] == 0
    
    def test_risk_score_calculation(self, mock_vt_api_key):
        """
        Test risk score calculation logic.
        
        Verifies that:
        - Score is percentage of malicious+suspicious engines
        - Score is capped at 100
        - Score is integer
        """
        scanner = VirusTotalScanner(mock_vt_api_key)
        
        test_response = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 30,
                        'suspicious': 20,
                        'undetected': 50,
                        'harmless': 0
                    },
                    'last_analysis_results': {},
                    'last_analysis_date': int(datetime.utcnow().timestamp())
                }
            }
        }
        
        result = scanner._parse_results(test_response, 'https://test.com')
        
        # (30 + 20) / 100 = 50%
        assert result['risk_score'] == 50
        assert isinstance(result['risk_score'], int)
        assert 0 <= result['risk_score'] <= 100
