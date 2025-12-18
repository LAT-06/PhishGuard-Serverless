import json
import os
import hashlib
from datetime import datetime, timedelta
from filelock import FileLock
from typing import Optional, Dict
from abc import ABC, abstractmethod


class CacheStrategy(ABC):
    """Abstract base class for cache storage strategies"""
    
    @abstractmethod
    def read(self) -> dict:
        pass
    
    @abstractmethod
    def write(self, data: dict) -> None:
        pass
    
    @abstractmethod
    def get_item(self, key: str) -> Optional[dict]:
        pass
    
    @abstractmethod
    def put_item(self, key: str, value: dict) -> None:
        pass
    
    @abstractmethod
    def delete_item(self, key: str) -> None:
        pass


class FileCacheStrategy(CacheStrategy):
    """Local file-based cache storage for development"""
    
    def __init__(self, cache_file: str):
        self.cache_file = cache_file
        self.lock_file = f"{cache_file}.lock"
        self._ensure_cache_directory()
    
    def _ensure_cache_directory(self):
        cache_dir = os.path.dirname(self.cache_file)
        if cache_dir and not os.path.exists(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)
        
        if not os.path.exists(self.cache_file):
            self.write({})
    
    def read(self) -> dict:
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
    
    def write(self, data: dict):
        lock = FileLock(self.lock_file, timeout=10)
        try:
            with lock:
                with open(self.cache_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise Exception(f"Error writing cache: {str(e)}")
    
    def get_item(self, key: str) -> Optional[dict]:
        cache_data = self.read()
        return cache_data.get(key)
    
    def put_item(self, key: str, value: dict) -> None:
        cache_data = self.read()
        cache_data[key] = value
        self.write(cache_data)
    
    def delete_item(self, key: str) -> None:
        cache_data = self.read()
        if key in cache_data:
            del cache_data[key]
            self.write(cache_data)


class DynamoDBCacheStrategy(CacheStrategy):
    """AWS DynamoDB-based cache storage for production"""
    
    def __init__(self, table_name: str):
        try:
            import boto3
            from botocore.exceptions import ClientError
            self.boto3 = boto3
            self.ClientError = ClientError
        except ImportError:
            raise ImportError("boto3 is required for DynamoDB support. Install with: pip install boto3")
        
        self.table_name = table_name
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(table_name)
    
    def read(self) -> dict:
        """Scan entire table (expensive operation, use sparingly)"""
        try:
            response = self.table.scan()
            items = response.get('Items', [])
            return {item['url_hash']: item for item in items}
        except self.ClientError as e:
            raise Exception(f"Error reading from DynamoDB: {str(e)}")
    
    def write(self, data: dict) -> None:
        """Batch write to DynamoDB"""
        try:
            with self.table.batch_writer() as batch:
                for key, value in data.items():
                    batch.put_item(Item={'url_hash': key, **value})
        except self.ClientError as e:
            raise Exception(f"Error writing to DynamoDB: {str(e)}")
    
    def get_item(self, key: str) -> Optional[dict]:
        try:
            response = self.table.get_item(Key={'url_hash': key})
            return response.get('Item')
        except self.ClientError as e:
            raise Exception(f"Error getting item from DynamoDB: {str(e)}")
    
    def put_item(self, key: str, value: dict) -> None:
        try:
            self.table.put_item(Item={'url_hash': key, **value})
        except self.ClientError as e:
            raise Exception(f"Error putting item to DynamoDB: {str(e)}")
    
    def delete_item(self, key: str) -> None:
        try:
            self.table.delete_item(Key={'url_hash': key})
        except self.ClientError as e:
            raise Exception(f"Error deleting item from DynamoDB: {str(e)}")


class CacheManager:
    """
    Cache manager that supports both local file and DynamoDB storage.
    Automatically selects strategy based on environment.
    """
    
    def __init__(self, resource_name: str, ttl_seconds: int = 3600):
        """
        Initialize cache manager with appropriate strategy.
        
        Args:
            resource_name: File path for local mode, table name for DynamoDB
            ttl_seconds: Time-to-live for cache entries in seconds
        """
        self.ttl_seconds = ttl_seconds
        self.is_serverless = os.environ.get('AWS_LAMBDA_FUNCTION_NAME') is not None
        
        if self.is_serverless:
            self.strategy = DynamoDBCacheStrategy(resource_name)
        else:
            self.strategy = FileCacheStrategy(resource_name)
    

    
    def generate_url_hash(self, url: str) -> str:
        return hashlib.sha256(url.encode('utf-8')).hexdigest()
    
    def is_expired(self, cache_entry: dict) -> bool:
        try:
            expires_at = datetime.fromisoformat(cache_entry['expires_at'])
            return datetime.utcnow() > expires_at
        except (KeyError, ValueError):
            return True
    
    def get_from_cache(self, url_hash: str) -> Optional[Dict]:
        cache_entry = self.strategy.get_item(url_hash)
        
        if not cache_entry:
            return None
        
        if self.is_expired(cache_entry):
            self.strategy.delete_item(url_hash)
            return None
        
        return cache_entry
    
    def save_to_cache(self, url_hash: str, data: dict) -> None:
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.ttl_seconds)
        
        cache_entry = {
            'url': data.get('url'),
            'result': data,
            'cached_at': now.isoformat(),
            'expires_at': expires_at.isoformat()
        }
        
        self.strategy.put_item(url_hash, cache_entry)
    
    def cleanup_expired(self) -> int:
        cache_data = self.strategy.read()
        expired_keys = []
        
        for url_hash, entry in cache_data.items():
            if self.is_expired(entry):
                expired_keys.append(url_hash)
        
        for key in expired_keys:
            self.strategy.delete_item(key)
        
        return len(expired_keys)
    
    def clear_all(self) -> int:
        cache_data = self.strategy.read()
        count = len(cache_data)
        self.strategy.write({})
        return count
    
    def get_cache_size(self) -> int:
        cache_data = self.strategy.read