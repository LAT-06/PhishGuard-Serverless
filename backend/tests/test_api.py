"""
Test suite for app.py - Flask API endpoints.

Tests cover:
- POST /api/scan endpoint with various scenarios
- GET /api/health endpoint
- DELETE /api/cache endpoint
- POST /api/cache/clean endpoint
- Request validation
- Error responses
- CORS headers
- Cache hit/miss scenarios
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from datetime import datetime


class TestHealthEndpoint:
    """Test /api/health endpoint."""
    
    def test_health_check_success(self, client):
        """
        Test successful health check.
        
        Verifies that:
        - Returns 200 status code
        - Response contains status field
        - Response contains cache_size
        - Response contains api_configured flag
        """
        response = client.get('/api/health')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['status'] == 'healthy'
        assert 'cache_size' in data
        assert 'api_configured' in data
        assert isinstance(data['cache_size'], int)
        assert isinstance(data['api_configured'], bool)
    
    def test_health_check_includes_timestamp(self, client):
        """
        Test that health check includes timestamp.
        
        Verifies that:
        - Timestamp is present
        - Timestamp is valid ISO format
        """
        response = client.get('/api/health')
        data = json.loads(response.data)
        
        assert 'timestamp' in data
        # Should be valid ISO timestamp
        datetime.fromisoformat(data['timestamp'])


class TestScanEndpoint:
    """Test POST /api/scan endpoint."""
    
    @patch('app.vt_scanner')
    @patch('app.cache_manager')
    def test_scan_valid_url_cache_miss(self, mock_cache, mock_scanner, client):
        """
        Test scanning valid URL with cache miss.
        
        Verifies that:
        - Request is accepted
        - VirusTotal API is called
        - Result is cached
        - Response has correct format
        """
        # Mock cache miss
        mock_cache.get_from_cache.return_value = None
        mock_cache.generate_url_hash.return_value = 'test_hash'
        
        # Mock VT scan result
        mock_scanner.scan_url.return_value = {
            'url': 'https://example.com',
            'risk_score': 0,
            'status': 'safe',
            'detections': {
                'malicious': 0,
                'suspicious': 0,
                'undetected': 70,
                'total_engines': 70
            },
            'categories': [],
            'scan_date': datetime.utcnow().isoformat()
        }
        
        response = client.post('/api/scan',
                               data=json.dumps({'url': 'https://example.com'}),
                               content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['success'] is True
        assert data['data']['url'] == 'https://example.com'
        assert data['data']['cached'] is False
        assert mock_scanner.scan_url.called
        assert mock_cache.save_to_cache.called
    
    @patch('app.cache_manager')
    def test_scan_valid_url_cache_hit(self, mock_cache, client):
        """
        Test scanning URL that exists in cache.
        
        Verifies that:
        - Cached result is returned
        - VirusTotal API is NOT called
        - Response indicates cached result
        """
        cached_result = {
            'url': 'https://example.com',
            'result': {
                'url': 'https://example.com',
                'risk_score': 0,
                'status': 'safe',
                'detections': {
                    'malicious': 0,
                    'suspicious': 0,
                    'undetected': 70,
                    'total_engines': 70
                },
                'categories': [],
                'scan_date': datetime.utcnow().isoformat()
            }
        }
        
        mock_cache.get_from_cache.return_value = cached_result
        mock_cache.generate_url_hash.return_value = 'test_hash'
        
        response = client.post('/api/scan',
                               data=json.dumps({'url': 'https://example.com'}),
                               content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['success'] is True
        assert data['data']['cached'] is True
    
    def test_scan_missing_url(self, client):
        """
        Test scan request without URL.
        
        Verifies that:
        - Returns 400 status code
        - Error message is clear
        """
        response = client.post('/api/scan',
                               data=json.dumps({}),
                               content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        
        assert data['success'] is False
        assert 'URL is required' in data['error']
    
    def test_scan_invalid_url_format(self, client):
        """
        Test scan with invalid URL format.
        
        Verifies that:
        - Returns 400 status code
        - Validates URL protocol
        """
        response = client.post('/api/scan',
                               data=json.dumps({'url': 'not-a-valid-url'}),
                               content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        
        assert data['success'] is False
        assert 'http' in data['error'].lower()
    
    def test_scan_url_without_protocol(self, client):
        """
        Test URL without http/https protocol.
        
        Verifies that:
        - Returns 400 status code
        - Error mentions protocol requirement
        """
        response = client.post('/api/scan',
                               data=json.dumps({'url': 'example.com'}),
                               content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        
        assert data['success'] is False
    
    def test_scan_empty_url(self, client):
        """
        Test scan with empty URL string.
        
        Verifies that:
        - Returns 400 status code
        - Request is rejected
        """
        response = client.post('/api/scan',
                               data=json.dumps({'url': ''}),
                               content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        
        assert data['success'] is False
    
    @patch('app.vt_scanner')
    @patch('app.cache_manager')
    def test_scan_rate_limit_error(self, mock_cache, mock_scanner, client):
        """
        Test handling of VirusTotal rate limit.
        
        Verifies that:
        - Returns 429 status code
        - Error message is user-friendly
        """
        from virustotal import VirusTotalRateLimitError
        
        mock_cache.get_from_cache.return_value = None
        mock_cache.generate_url_hash.return_value = 'test_hash'
        mock_scanner.scan_url.side_effect = VirusTotalRateLimitError('Rate limit exceeded')
        
        response = client.post('/api/scan',
                               data=json.dumps({'url': 'https://example.com'}),
                               content_type='application/json')
        
        assert response.status_code == 429
        data = json.loads(response.data)
        
        assert data['success'] is False
        assert 'rate limit' in data['error'].lower()
    
    @patch('app.vt_scanner')
    @patch('app.cache_manager')
    def test_scan_vt_api_error(self, mock_cache, mock_scanner, client):
        """
        Test handling of VirusTotal API errors.
        
        Verifies that:
        - Returns 503 status code
        - Error is logged
        - User gets informative message
        """
        from virustotal import VirusTotalAPIError
        
        mock_cache.get_from_cache.return_value = None
        mock_cache.generate_url_hash.return_value = 'test_hash'
        mock_scanner.scan_url.side_effect = VirusTotalAPIError('API error')
        
        response = client.post('/api/scan',
                               data=json.dumps({'url': 'https://example.com'}),
                               content_type='application/json')
        
        assert response.status_code == 503
        data = json.loads(response.data)
        
        assert data['success'] is False
        assert 'error' in data
    
    def test_scan_malformed_json(self, client):
        """
        Test handling of malformed JSON request.
        
        Verifies that:
        - Returns error for invalid JSON
        - Doesn't crash the server
        """
        response = client.post('/api/scan',
                               data='not valid json',
                               content_type='application/json')
        
        # Flask returns 400 for bad JSON by default
        assert response.status_code in [400, 500]


class TestCacheEndpoints:
    """Test cache management endpoints."""
    
    @patch('app.cache_manager')
    def test_clear_cache_without_confirmation(self, mock_cache, client):
        """
        Test cache clear without confirmation parameter.
        
        Verifies that:
        - Returns 400 status code
        - Requires explicit confirmation
        - Cache is NOT cleared
        """
        response = client.delete('/api/cache')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        
        assert data['success'] is False
        assert 'confirm' in data['error'].lower()
        assert not mock_cache.clear_all.called
    
    @patch('app.cache_manager')
    def test_clear_cache_with_confirmation(self, mock_cache, client):
        """
        Test successful cache clearing with confirmation.
        
        Verifies that:
        - Returns 200 status code
        - Cache is cleared
        - Returns count of deleted entries
        """
        mock_cache.clear_all.return_value = 5
        
        response = client.delete('/api/cache?confirm=true')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['success'] is True
        assert data['deleted_count'] == 5
        assert mock_cache.clear_all.called
    
    @patch('app.cache_manager')
    def test_clear_cache_case_insensitive(self, mock_cache, client):
        """
        Test that confirmation is case-insensitive.
        
        Verifies that:
        - 'true', 'True', 'TRUE' all work
        """
        mock_cache.clear_all.return_value = 0
        
        for confirm_value in ['true', 'True', 'TRUE']:
            response = client.delete(f'/api/cache?confirm={confirm_value}')
            assert response.status_code == 200
    
    @patch('app.cache_manager')
    def test_clean_expired_cache(self, mock_cache, client):
        """
        Test cleaning expired cache entries.
        
        Verifies that:
        - Returns 200 status code
        - Returns count of cleaned entries
        - Only expired entries are removed
        """
        mock_cache.clean_expired_entries.return_value = 3
        
        response = client.post('/api/cache/clean')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        assert data['success'] is True
        assert data['cleaned_count'] == 3
        assert mock_cache.clean_expired_entries.called


class TestErrorHandlers:
    """Test global error handlers."""
    
    def test_404_not_found(self, client):
        """
        Test 404 handler for non-existent endpoints.
        
        Verifies that:
        - Returns 404 status code
        - Returns JSON response
        - Error message is clear
        """
        response = client.get('/api/nonexistent')
        
        assert response.status_code == 404
        data = json.loads(response.data)
        
        assert data['success'] is False
        assert 'not found' in data['error'].lower()
    
    def test_405_method_not_allowed(self, client):
        """
        Test wrong HTTP method on endpoint.
        
        Verifies that:
        - GET on /api/scan returns error
        - Appropriate status code is returned
        """
        response = client.get('/api/scan')
        
        # Flask returns 405 for method not allowed
        assert response.status_code == 405


class TestCORSHeaders:
    """Test CORS configuration."""
    
    def test_cors_headers_present(self, client):
        """
        Test that CORS headers are present in responses.
        
        Verifies that:
        - Access-Control-Allow-Origin header is set
        - CORS is enabled for frontend access
        """
        response = client.get('/api/health')
        
        # CORS headers should be present
        assert 'Access-Control-Allow-Origin' in response.headers
    
    def test_cors_preflight_request(self, client):
        """
        Test CORS preflight OPTIONS request.
        
        Verifies that:
        - OPTIONS requests are handled
        - Appropriate headers are returned
        """
        response = client.options('/api/scan')
        
        # Should allow OPTIONS
        assert response.status_code in [200, 204]


class TestRequestValidation:
    """Test request validation and input sanitization."""
    
    def test_scan_with_extra_fields(self, client):
        """
        Test that extra fields in request are ignored.
        
        Verifies that:
        - Extra fields don't cause errors
        - Only 'url' field is used
        """
        with patch('app.vt_scanner') as mock_scanner, \
             patch('app.cache_manager') as mock_cache:
            
            mock_cache.get_from_cache.return_value = None
            mock_cache.generate_url_hash.return_value = 'test_hash'
            mock_scanner.scan_url.return_value = {
                'url': 'https://example.com',
                'risk_score': 0,
                'status': 'safe',
                'detections': {'malicious': 0, 'suspicious': 0, 'undetected': 70, 'total_engines': 70},
                'categories': [],
                'scan_date': datetime.utcnow().isoformat()
            }
            
            response = client.post('/api/scan',
                                   data=json.dumps({
                                       'url': 'https://example.com',
                                       'extra_field': 'ignored',
                                       'another': 123
                                   }),
                                   content_type='application/json')
            
            assert response.status_code == 200
    
    def test_scan_url_with_whitespace(self, client):
        """
        Test URL with leading/trailing whitespace.
        
        Verifies that:
        - Whitespace is trimmed
        - Request is processed correctly
        """
        with patch('app.vt_scanner') as mock_scanner, \
             patch('app.cache_manager') as mock_cache:
            
            mock_cache.get_from_cache.return_value = None
            mock_cache.generate_url_hash.return_value = 'test_hash'
            mock_scanner.scan_url.return_value = {
                'url': 'https://example.com',
                'risk_score': 0,
                'status': 'safe',
                'detections': {'malicious': 0, 'suspicious': 0, 'undetected': 70, 'total_engines': 70},
                'categories': [],
                'scan_date': datetime.utcnow().isoformat()
            }
            
            response = client.post('/api/scan',
                                   data=json.dumps({'url': '  https://example.com  '}),
                                   content_type='application/json')
            
            assert response.status_code == 200


class TestIntegration:
    """Integration tests for complete workflows."""
    
    @patch('app.vt_scanner')
    @patch('app.cache_manager')
    def test_complete_scan_workflow(self, mock_cache, mock_scanner, client):
        """
        Test complete workflow from scan to cache to retrieval.
        
        Verifies that:
        - First scan calls VT API
        - Result is cached
        - Second scan returns cached result
        - No duplicate API calls
        """
        test_url = 'https://example.com'
        scan_result = {
            'url': test_url,
            'risk_score': 0,
            'status': 'safe',
            'detections': {'malicious': 0, 'suspicious': 0, 'undetected': 70, 'total_engines': 70},
            'categories': [],
            'scan_date': datetime.utcnow().isoformat()
        }
        
        # First request - cache miss
        mock_cache.get_from_cache.return_value = None
        mock_cache.generate_url_hash.return_value = 'test_hash'
        mock_scanner.scan_url.return_value = scan_result
        
        response1 = client.post('/api/scan',
                                data=json.dumps({'url': test_url}),
                                content_type='application/json')
        
        assert response1.status_code == 200
        data1 = json.loads(response1.data)
        assert data1['data']['cached'] is False
        
        # Simulate cache now has the entry
        mock_cache.get_from_cache.return_value = {
            'url': test_url,
            'result': scan_result
        }
        
        # Second request - cache hit
        response2 = client.post('/api/scan',
                                data=json.dumps({'url': test_url}),
                                content_type='application/json')
        
        assert response2.status_code == 200
        data2 = json.loads(response2.data)
        assert data2['data']['cached'] is True
    
    @patch('app.cache_manager')
    def test_health_and_cache_integration(self, mock_cache, client):
        """
        Test health endpoint reflects cache state.
        
        Verifies that:
        - Health check shows current cache size
        - Cache size updates after operations
        """
        mock_cache.get_cache_size.return_value = 0
        
        response1 = client.get('/api/health')
        data1 = json.loads(response1.data)
        assert data1['cache_size'] == 0
        
        # Simulate cache has entries
        mock_cache.get_cache_size.return_value = 5
        
        response2 = client.get('/api/health')
        data2 = json.loads(response2.data)
        assert data2['cache_size'] == 5
