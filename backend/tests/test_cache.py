"""
Test suite for cache.py - File-based caching with thread safety.

Tests cover:
- Basic cache operations (save, retrieve, delete)
- Cache expiration logic
- Thread-safe concurrent access
- Error handling for corrupted files
- Cache cleanup operations
"""

import pytest
import os
import json
import time
import threading
from datetime import datetime, timedelta
from cache import CacheManager


class TestCacheBasicOperations:
    """Test basic cache CRUD operations."""
    
    def test_save_to_cache(self, cache_manager):
        """
        Test saving data to cache.
        
        Verifies that:
        - Data is saved correctly
        - Cache file is created
        - Cache entry includes all required fields
        """
        url_hash = cache_manager.generate_url_hash('https://example.com')
        test_data = {
            'url': 'https://example.com',
            'risk_score': 0,
            'status': 'safe'
        }
        
        cache_manager.save_to_cache(url_hash, test_data)
        
        # Verify cache file exists
        assert os.path.exists(cache_manager.cache_file)
        
        # Verify data was saved
        with open(cache_manager.cache_file, 'r') as f:
            cache_data = json.load(f)
            assert url_hash in cache_data
            assert cache_data[url_hash]['url'] == 'https://example.com'
            assert 'cached_at' in cache_data[url_hash]
            assert 'expires_at' in cache_data[url_hash]
    
    def test_retrieve_from_cache(self, cache_manager):
        """
        Test retrieving data from cache.
        
        Verifies that:
        - Saved data can be retrieved
        - Retrieved data matches saved data
        """
        url_hash = cache_manager.generate_url_hash('https://example.com')
        test_data = {
            'url': 'https://example.com',
            'risk_score': 0,
            'status': 'safe'
        }
        
        cache_manager.save_to_cache(url_hash, test_data)
        retrieved = cache_manager.get_from_cache(url_hash)
        
        assert retrieved is not None
        assert retrieved['url'] == 'https://example.com'
        assert retrieved['result']['risk_score'] == 0
    
    def test_cache_miss(self, cache_manager):
        """
        Test cache miss scenario.
        
        Verifies that:
        - Non-existent keys return None
        - No error is raised
        """
        url_hash = cache_manager.generate_url_hash('https://nonexistent.com')
        result = cache_manager.get_from_cache(url_hash)
        
        assert result is None
    
    def test_cache_size(self, cache_manager):
        """
        Test cache size tracking.
        
        Verifies that:
        - get_cache_size returns correct count
        - Count updates when adding/removing entries
        """
        assert cache_manager.get_cache_size() == 0
        
        # Add entries
        for i in range(5):
            url_hash = cache_manager.generate_url_hash(f'https://example{i}.com')
            cache_manager.save_to_cache(url_hash, {'url': f'https://example{i}.com'})
        
        assert cache_manager.get_cache_size() == 5
    
    def test_clear_all_cache(self, cache_manager):
        """
        Test clearing entire cache.
        
        Verifies that:
        - All entries are removed
        - Returns correct count of deleted entries
        - Cache file still exists but is empty
        """
        # Add entries
        for i in range(3):
            url_hash = cache_manager.generate_url_hash(f'https://example{i}.com')
            cache_manager.save_to_cache(url_hash, {'url': f'https://example{i}.com'})
        
        count = cache_manager.clear_all()
        
        assert count == 3
        assert cache_manager.get_cache_size() == 0
        assert os.path.exists(cache_manager.cache_file)


class TestCacheExpiration:
    """Test cache expiration logic."""
    
    def test_is_expired_fresh_entry(self, cache_manager, mock_cache_entry):
        """
        Test that fresh cache entries are not expired.
        
        Verifies that:
        - Recently cached entries return False for is_expired
        """
        assert not cache_manager.is_expired(mock_cache_entry)
    
    def test_is_expired_old_entry(self, cache_manager, mock_expired_cache_entry):
        """
        Test that old cache entries are expired.
        
        Verifies that:
        - Entries past TTL return True for is_expired
        """
        assert cache_manager.is_expired(mock_expired_cache_entry)
    
    def test_expired_entry_removed_on_get(self, cache_manager):
        """
        Test that expired entries are automatically removed.
        
        Verifies that:
        - get_from_cache removes expired entries
        - Returns None for expired entries
        - Entry is deleted from cache file
        """
        # Create cache with short TTL
        short_ttl_manager = CacheManager(cache_manager.cache_file, ttl_seconds=1)
        
        url_hash = short_ttl_manager.generate_url_hash('https://example.com')
        test_data = {'url': 'https://example.com', 'risk_score': 0}
        
        short_ttl_manager.save_to_cache(url_hash, test_data)
        
        # Wait for expiration
        time.sleep(2)
        
        # Should return None and remove entry
        result = short_ttl_manager.get_from_cache(url_hash)
        assert result is None
        assert short_ttl_manager.get_cache_size() == 0
    
    def test_clean_expired_entries(self, cache_manager):
        """
        Test manual cleanup of expired entries.
        
        Verifies that:
        - clean_expired_entries removes all expired entries
        - Returns correct count of cleaned entries
        - Valid entries remain in cache
        """
        # Add mix of fresh and expired entries
        short_ttl_manager = CacheManager(cache_manager.cache_file, ttl_seconds=1)
        
        # Add entries that will expire
        for i in range(3):
            url_hash = short_ttl_manager.generate_url_hash(f'https://old{i}.com')
            short_ttl_manager.save_to_cache(url_hash, {'url': f'https://old{i}.com'})
        
        time.sleep(2)
        
        # Add fresh entries
        long_ttl_manager = CacheManager(cache_manager.cache_file, ttl_seconds=3600)
        for i in range(2):
            url_hash = long_ttl_manager.generate_url_hash(f'https://new{i}.com')
            long_ttl_manager.save_to_cache(url_hash, {'url': f'https://new{i}.com'})
        
        # Clean expired
        cleaned = long_ttl_manager.clean_expired_entries()
        
        assert cleaned == 3
        assert long_ttl_manager.get_cache_size() == 2


class TestCacheThreadSafety:
    """Test thread-safe concurrent cache operations."""
    
    def test_concurrent_writes(self, cache_manager):
        """
        Test multiple threads writing to cache simultaneously.
        
        Verifies that:
        - File locking prevents data corruption
        - All writes complete successfully
        - No data is lost
        """
        def write_to_cache(url_suffix):
            url = f'https://concurrent{url_suffix}.com'
            url_hash = cache_manager.generate_url_hash(url)
            cache_manager.save_to_cache(url_hash, {'url': url})
        
        threads = []
        for i in range(10):
            thread = threading.Thread(target=write_to_cache, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify all entries were saved
        assert cache_manager.get_cache_size() == 10
    
    def test_concurrent_read_write(self, cache_manager):
        """
        Test simultaneous reads and writes.
        
        Verifies that:
        - Reads don't block writes and vice versa
        - Data consistency is maintained
        - No race conditions occur
        """
        results = []
        
        # Pre-populate cache
        url_hash = cache_manager.generate_url_hash('https://shared.com')
        cache_manager.save_to_cache(url_hash, {'url': 'https://shared.com', 'value': 0})
        
        def read_cache():
            for _ in range(5):
                result = cache_manager.get_from_cache(url_hash)
                results.append(result)
                time.sleep(0.01)
        
        def write_cache():
            for i in range(5):
                cache_manager.save_to_cache(url_hash, {'url': 'https://shared.com', 'value': i})
                time.sleep(0.01)
        
        read_thread = threading.Thread(target=read_cache)
        write_thread = threading.Thread(target=write_cache)
        
        read_thread.start()
        write_thread.start()
        
        read_thread.join()
        write_thread.join()
        
        # All reads should have succeeded
        assert len(results) == 5
        assert all(r is not None for r in results)


class TestCacheErrorHandling:
    """Test cache error handling and edge cases."""
    
    def test_corrupted_cache_file(self, corrupted_cache_file):
        """
        Test handling of corrupted cache file.
        
        Verifies that:
        - Corrupted JSON doesn't crash the system
        - Returns empty cache instead of error
        - System can recover by writing new data
        """
        cache_manager = CacheManager(corrupted_cache_file)
        
        # Should not raise error, should return None
        url_hash = cache_manager.generate_url_hash('https://test.com')
        result = cache_manager.get_from_cache(url_hash)
        
        assert result is None
        
        # Should be able to write new data
        cache_manager.save_to_cache(url_hash, {'url': 'https://test.com'})
        assert cache_manager.get_cache_size() == 1
    
    def test_missing_cache_directory(self, temp_cache_file):
        """
        Test auto-creation of cache directory.
        
        Verifies that:
        - Non-existent directories are created automatically
        - Cache operations work after directory creation
        """
        # Use path in non-existent directory
        import tempfile
        temp_dir = tempfile.mkdtemp()
        cache_path = os.path.join(temp_dir, 'subdir', 'cache.json')
        
        # Remove temp directory to test creation
        os.rmdir(temp_dir)
        
        cache_manager = CacheManager(cache_path)
        
        # Should create directory and file
        url_hash = cache_manager.generate_url_hash('https://test.com')
        cache_manager.save_to_cache(url_hash, {'url': 'https://test.com'})
        
        assert os.path.exists(cache_path)
        
        # Cleanup
        import shutil
        shutil.rmtree(os.path.dirname(cache_path))
    
    def test_empty_cache_file(self, temp_cache_file):
        """
        Test handling of empty cache file.
        
        Verifies that:
        - Empty file is handled gracefully
        - Can write to empty cache
        """
        # Create empty file
        with open(temp_cache_file, 'w') as f:
            f.write('')
        
        cache_manager = CacheManager(temp_cache_file)
        
        # Should not crash
        assert cache_manager.get_cache_size() == 0
        
        # Should be able to write
        url_hash = cache_manager.generate_url_hash('https://test.com')
        cache_manager.save_to_cache(url_hash, {'url': 'https://test.com'})
        assert cache_manager.get_cache_size() == 1


class TestCacheURLHashing:
    """Test URL hashing functionality."""
    
    def test_generate_url_hash_consistency(self, cache_manager):
        """
        Test that same URL produces same hash.
        
        Verifies that:
        - Hash is deterministic
        - Same URL always produces same hash
        """
        url = 'https://example.com'
        hash1 = cache_manager.generate_url_hash(url)
        hash2 = cache_manager.generate_url_hash(url)
        
        assert hash1 == hash2
    
    def test_different_urls_different_hashes(self, cache_manager):
        """
        Test that different URLs produce different hashes.
        
        Verifies that:
        - Hash collision is avoided
        - Each URL gets unique identifier
        """
        hash1 = cache_manager.generate_url_hash('https://example1.com')
        hash2 = cache_manager.generate_url_hash('https://example2.com')
        
        assert hash1 != hash2
    
    def test_hash_length(self, cache_manager):
        """
        Test that hash has expected length (SHA256 = 64 chars).
        
        Verifies that:
        - Hash is 64 characters (SHA256 hex)
        - Hash contains only hexadecimal characters
        """
        url_hash = cache_manager.generate_url_hash('https://example.com')
        
        assert len(url_hash) == 64
        assert all(c in '0123456789abcdef' for c in url_hash)
