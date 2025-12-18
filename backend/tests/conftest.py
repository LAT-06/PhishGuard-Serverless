"""
Pytest configuration and shared fixtures for backend testing.

This module provides reusable test fixtures that are automatically
discovered by pytest. Fixtures defined here are available to all test files.
"""

import pytest
import os
import tempfile
import json
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

# Import application modules
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app as flask_app
from cache import CacheManager
from virustotal import VirusTotalScanner


@pytest.fixture
def app():
    """
    Create and configure a Flask application instance for testing.
    
    Yields:
        Flask: Configured Flask application in testing mode
    """
    flask_app.config['TESTING'] = True
    flask_app.config['DEBUG'] = False
    yield flask_app


@pytest.fixture
def client(app):
    """
    Create a test client for making HTTP requests.
    
    Args:
        app: Flask application fixture
        
    Yields:
        FlaskClient: Test client for API endpoint testing
    """
    return app.test_client()


@pytest.fixture
def temp_cache_file():
    """
    Create a temporary cache file for testing.
    
    This fixture creates a temporary file that is automatically
    cleaned up after the test completes.
    
    Yields:
        str: Path to temporary cache file
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{}')
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    try:
        os.unlink(temp_file)
        lock_file = f"{temp_file}.lock"
        if os.path.exists(lock_file):
            os.unlink(lock_file)
    except Exception:
        pass


@pytest.fixture
def cache_manager(temp_cache_file):
    """
    Create a CacheManager instance with temporary cache file.
    
    Args:
        temp_cache_file: Temporary cache file fixture
        
    Returns:
        CacheManager: Configured cache manager for testing
    """
    return CacheManager(temp_cache_file, ttl_seconds=3600)


@pytest.fixture
def mock_vt_success_response():
    """
    Mock successful VirusTotal API response.
    
    Returns:
        dict: Sample VT response for a safe URL
    """
    return {
        'data': {
            'id': 'test-analysis-id',
            'type': 'analysis',
            'attributes': {
                'last_analysis_stats': {
                    'malicious': 0,
                    'suspicious': 0,
                    'undetected': 70,
                    'harmless': 15,
                    'timeout': 0
                },
                'last_analysis_results': {},
                'last_analysis_date': int(datetime.utcnow().timestamp())
            }
        }
    }


@pytest.fixture
def mock_vt_malicious_response():
    """
    Mock VirusTotal API response for malicious URL.
    
    Returns:
        dict: Sample VT response for a malicious URL
    """
    return {
        'data': {
            'id': 'test-analysis-id-malicious',
            'type': 'analysis',
            'attributes': {
                'last_analysis_stats': {
                    'malicious': 45,
                    'suspicious': 10,
                    'undetected': 25,
                    'harmless': 5,
                    'timeout': 0
                },
                'last_analysis_results': {
                    'Engine1': {
                        'category': 'malicious',
                        'result': 'phishing',
                        'engine_name': 'Engine1'
                    },
                    'Engine2': {
                        'category': 'malicious',
                        'result': 'malware',
                        'engine_name': 'Engine2'
                    }
                },
                'last_analysis_date': int(datetime.utcnow().timestamp())
            }
        }
    }


@pytest.fixture
def sample_urls():
    """
    Sample URLs for testing.
    
    Returns:
        dict: Collection of test URLs with categories
    """
    return {
        'valid_safe': 'https://example.com',
        'valid_suspicious': 'https://test-phishing-site.com',
        'valid_malicious': 'https://known-malware-site.com',
        'invalid_no_protocol': 'example.com',
        'invalid_wrong_protocol': 'ftp://example.com',
        'invalid_malformed': 'not-a-url',
        'empty': ''
    }


@pytest.fixture
def mock_cache_entry():
    """
    Sample cache entry for testing.
    
    Returns:
        dict: Complete cache entry with all fields
    """
    now = datetime.utcnow()
    return {
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
            'scan_date': now.isoformat()
        },
        'cached_at': now.isoformat(),
        'expires_at': (now + timedelta(hours=1)).isoformat()
    }


@pytest.fixture
def mock_expired_cache_entry():
    """
    Expired cache entry for testing expiration logic.
    
    Returns:
        dict: Cache entry that has already expired
    """
    past = datetime.utcnow() - timedelta(hours=2)
    return {
        'url': 'https://expired.com',
        'result': {
            'url': 'https://expired.com',
            'risk_score': 0,
            'status': 'safe',
            'detections': {
                'malicious': 0,
                'suspicious': 0,
                'undetected': 70,
                'total_engines': 70
            },
            'categories': [],
            'scan_date': past.isoformat()
        },
        'cached_at': past.isoformat(),
        'expires_at': (past + timedelta(hours=1)).isoformat()
    }


@pytest.fixture
def mock_vt_api_key():
    """
    Mock VirusTotal API key for testing.
    
    Returns:
        str: Fake API key
    """
    return 'test_api_key_1234567890abcdef'


@pytest.fixture
def mock_requests_post():
    """
    Mock requests.post for VirusTotal API calls.
    
    Yields:
        MagicMock: Mocked requests.post function
    """
    with patch('virustotal.requests.request') as mock_request:
        yield mock_request


@pytest.fixture
def mock_successful_vt_scanner(mock_vt_api_key):
    """
    Mock VirusTotalScanner that returns successful responses.
    
    Args:
        mock_vt_api_key: Mock API key fixture
        
    Returns:
        VirusTotalScanner: Mocked scanner instance
    """
    scanner = VirusTotalScanner(mock_vt_api_key)
    
    # Mock the scan_url method
    scanner.scan_url = MagicMock(return_value={
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
    })
    
    return scanner


@pytest.fixture(autouse=True)
def mock_environment():
    """
    Mock environment variables for testing.
    
    This fixture automatically runs for all tests to ensure
    consistent test environment.
    """
    with patch.dict(os.environ, {
        'VIRUSTOTAL_API_KEY': 'test_api_key_1234567890',
        'FLASK_DEBUG': 'False',
        'CACHE_TTL': '3600'
    }):
        yield


@pytest.fixture
def corrupted_cache_file():
    """
    Create a cache file with corrupted JSON for testing error handling.
    
    Yields:
        str: Path to corrupted cache file
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{"invalid": json content}')
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    try:
        os.unlink(temp_file)
        lock_file = f"{temp_file}.lock"
        if os.path.exists(lock_file):
            os.unlink(lock_file)
    except Exception:
        pass
