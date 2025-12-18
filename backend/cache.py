import json
import os
import hashlib
from datetime import datetime, timedelta
from filelock import FileLock
from typing import Optional, Dict


class CacheManager:
    def __init__(self, cache_file: str, ttl_seconds: int = 3600):
        self.cache_file = cache_file
        self.lock_file = f"{cache_file}.lock"
        self.ttl_seconds = ttl_seconds
        self._ensure_cache_directory()
    
    def _ensure_cache_directory(self):
        cache_dir = os.path.dirname(self.cache_file)
        if cache_dir and not os.path.exists(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)
        
        if not os.path.exists(self.cache_file):
            self._write_cache({})
    
    def _read_cache(self) -> dict:
        lock = FileLock(self.lock_file, timeout=10)
        try:
            with lock:
                if not os.path.exists(self.cache_file):
                    return {}
                
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if not content:
                        return {}
                    return json.loads(content)
        except json.JSONDecodeError:
            return {}
        except Exception as e:
            raise Exception(f"Error reading cache: {str(e)}")
    
    def _write_cache(self, cache_data: dict):
        lock = FileLock(self.lock_file, timeout=10)
        try:
            with lock:
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    json.dump(cache_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise Exception(f"Error writing cache: {str(e)}")
    
    def generate_url_hash(self, url: str) -> str:
        return hashlib.sha256(url.encode('utf-8')).hexdigest()
    
    def is_expired(self, cache_entry: dict) -> bool:
        try:
            expires_at = datetime.fromisoformat(cache_entry['expires_at'])
            return datetime.utcnow() > expires_at
        except (KeyError, ValueError):
            return True
    
    def get_from_cache(self, url_hash: str) -> Optional[Dict]:
        cache_data = self._read_cache()
        
        if url_hash not in cache_data:
            return None
        
        cache_entry = cache_data[url_hash]
        
        if self.is_expired(cache_entry):
            del cache_data[url_hash]
            self._write_cache(cache_data)
            return None
        
        return cache_entry
    
    def save_to_cache(self, url_hash: str, data: dict) -> None:
        cache_data = self._read_cache()
        
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.ttl_seconds)
        
        cache_entry = {
            'url': data.get('url'),
            'result': data,
            'cached_at': now.isoformat(),
            'expires_at': expires_at.isoformat()
        }
        
        cache_data[url_hash] = cache_entry
        self._write_cache(cache_data)
    
    def clean_expired_entries(self) -> int:
        cache_data = self._read_cache()
        expired_keys = []
        
        for url_hash, entry in cache_data.items():
            if self.is_expired(entry):
                expired_keys.append(url_hash)
        
        for key in expired_keys:
            del cache_data[key]
        
        if expired_keys:
            self._write_cache(cache_data)
        
        return len(expired_keys)
    
    def clear_all(self) -> int:
        cache_data = self._read_cache()
        count = len(cache_data)
        self._write_cache({})
        return count
    
    def get_cache_size(self) -> int:
        cache_data = self._read_cache()
        return len(cache_data)
