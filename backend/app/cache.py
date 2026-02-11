# services/backend/app/cache.py
"""
Simple in-memory cache manager with TTL support
"""

from datetime import datetime, timedelta
from typing import Any, Optional
import re

class CacheManager:
    """In-memory cache with TTL expiration."""
    
    def __init__(self, ttl: int = 300):
        """Initialize cache with TTL in seconds."""
        self.ttl = ttl
        self._cache = {}
        self._expiry = {}
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Store value in cache."""
        self._cache[key] = value
        expiry_time = datetime.utcnow() + timedelta(seconds=ttl or self.ttl)
        self._expiry[key] = expiry_time
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve value from cache if not expired."""
        if key not in self._cache:
            return None
        
        # Check expiration
        if datetime.utcnow() > self._expiry.get(key, datetime.utcnow()):
            del self._cache[key]
            if key in self._expiry:
                del self._expiry[key]
            return None
        
        return self._cache[key]
    
    def delete(self, key: str):
        """Delete a cache entry."""
        if key in self._cache:
            del self._cache[key]
        if key in self._expiry:
            del self._expiry[key]
    
    def clear(self):
        """Clear entire cache."""
        self._cache.clear()
        self._expiry.clear()
    
    def invalidate_pattern(self, pattern: str):
        """Invalidate all keys matching a pattern."""
        regex = re.compile(pattern)
        keys_to_delete = [k for k in self._cache.keys() if regex.match(k)]
        for key in keys_to_delete:
            self.delete(key)
    
    def get_stats(self) -> dict:
        """Get cache statistics."""
        return {
            "entries": len(self._cache),
            "ttl": self.ttl
        }
