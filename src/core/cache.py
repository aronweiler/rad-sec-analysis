"""
Caching System

Simple in-memory caching for LLM responses and tool results to improve efficiency.
"""

import hashlib
import json
import time
import logging
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass
from collections import OrderedDict

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    value: Any
    created_at: float
    ttl: int
    access_count: int = 0
    last_accessed: float = 0.0
    
    def __post_init__(self):
        if self.last_accessed == 0.0:
            self.last_accessed = self.created_at
    
    @property
    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return time.time() > (self.created_at + self.ttl)
    
    @property
    def age_seconds(self) -> float:
        """Get age of cache entry in seconds"""
        return time.time() - self.created_at
    
    def touch(self):
        """Update access information"""
        self.access_count += 1
        self.last_accessed = time.time()


class MemoryCache:
    """Simple in-memory cache with TTL and LRU eviction"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "expired_removals": 0
        }
    
    def _generate_key(self, key_data: Any) -> str:
        """Generate cache key from data"""
        if isinstance(key_data, str):
            return key_data
        
        # Create deterministic hash from data
        serialized = json.dumps(key_data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()[:16]
    
    def get(self, key: Any) -> Optional[Any]:
        """Get value from cache"""
        cache_key = self._generate_key(key)
        
        if cache_key not in self._cache:
            self._stats["misses"] += 1
            return None
        
        entry = self._cache[cache_key]
        
        # Check if expired
        if entry.is_expired:
            del self._cache[cache_key]
            self._stats["expired_removals"] += 1
            self._stats["misses"] += 1
            return None
        
        # Update access info and move to end (most recently used)
        entry.touch()
        self._cache.move_to_end(cache_key)
        
        self._stats["hits"] += 1
        logger.debug(f"Cache hit for key: {cache_key[:8]}...")
        
        return entry.value
    
    def set(self, key: Any, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache"""
        cache_key = self._generate_key(key)
        ttl = ttl or self.default_ttl
        
        # Create cache entry
        entry = CacheEntry(
            value=value,
            created_at=time.time(),
            ttl=ttl
        )
        
        # Add to cache
        self._cache[cache_key] = entry
        self._cache.move_to_end(cache_key)
        
        # Evict if necessary
        self._evict_if_needed()
        
        logger.debug(f"Cached value for key: {cache_key[:8]}... (TTL: {ttl}s)")
    
    def _evict_if_needed(self):
        """Evict oldest entries if cache is full"""
        while len(self._cache) > self.max_size:
            # Remove least recently used item
            oldest_key, _ = self._cache.popitem(last=False)
            self._stats["evictions"] += 1
            logger.debug(f"Evicted cache entry: {oldest_key[:8]}...")
    
    def delete(self, key: Any) -> bool:
        """Delete entry from cache"""
        cache_key = self._generate_key(key)
        
        if cache_key in self._cache:
            del self._cache[cache_key]
            logger.debug(f"Deleted cache entry: {cache_key[:8]}...")
            return True
        
        return False
    
    def clear(self):
        """Clear all cache entries"""
        self._cache.clear()
        logger.info("Cache cleared")
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed"""
        expired_keys = []
        current_time = time.time()
        
        for key, entry in self._cache.items():
            if current_time > (entry.created_at + entry.ttl):
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._cache[key]
            self._stats["expired_removals"] += 1
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
        
        return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total_requests) if total_requests > 0 else 0.0
        
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._stats["hits"],
            "misses": self._stats["misses"],
            "hit_rate": hit_rate,
            "evictions": self._stats["evictions"],
            "expired_removals": self._stats["expired_removals"],
            "total_requests": total_requests
        }
    
    def get_entry_info(self, key: Any) -> Optional[Dict[str, Any]]:
        """Get information about a cache entry"""
        cache_key = self._generate_key(key)
        
        if cache_key not in self._cache:
            return None
        
        entry = self._cache[cache_key]
        
        return {
            "key": cache_key,
            "created_at": entry.created_at,
            "ttl": entry.ttl,
            "age_seconds": entry.age_seconds,
            "access_count": entry.access_count,
            "last_accessed": entry.last_accessed,
            "is_expired": entry.is_expired
        }


class ResponseCache:
    """Specialized cache for LLM responses and tool results"""
    
    def __init__(self, max_size: int = 500, default_ttl: int = 3600):
        self.cache = MemoryCache(max_size, default_ttl)
    
    def cache_llm_response(
        self, 
        prompt: str, 
        model: str, 
        response: str,
        metadata: Optional[Dict[str, Any]] = None,
        ttl: Optional[int] = None
    ) -> None:
        """Cache an LLM response"""
        cache_key = {
            "type": "llm_response",
            "prompt": prompt,
            "model": model
        }
        
        cache_value = {
            "response": response,
            "metadata": metadata or {},
            "cached_at": time.time()
        }
        
        self.cache.set(cache_key, cache_value, ttl)
    
    def get_llm_response(self, prompt: str, model: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Get cached LLM response"""
        cache_key = {
            "type": "llm_response",
            "prompt": prompt,
            "model": model
        }
        
        cached = self.cache.get(cache_key)
        if cached:
            return cached["response"], cached["metadata"]
        
        return None
    
    def cache_tool_result(
        self, 
        tool_name: str, 
        arguments: Dict[str, Any], 
        result: Any,
        ttl: Optional[int] = None
    ) -> None:
        """Cache a tool result"""
        cache_key = {
            "type": "tool_result",
            "tool_name": tool_name,
            "arguments": arguments
        }
        
        cache_value = {
            "result": result,
            "cached_at": time.time()
        }
        
        self.cache.set(cache_key, cache_value, ttl)
    
    def get_tool_result(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[Any]:
        """Get cached tool result"""
        cache_key = {
            "type": "tool_result",
            "tool_name": tool_name,
            "arguments": arguments
        }
        
        cached = self.cache.get(cache_key)
        if cached:
            return cached["result"]
        
        return None
    
    def cache_reasoning_decision(
        self, 
        stage: str, 
        context_hash: str, 
        decision: Dict[str, Any],
        ttl: Optional[int] = None
    ) -> None:
        """Cache a reasoning decision"""
        cache_key = {
            "type": "reasoning_decision",
            "stage": stage,
            "context_hash": context_hash
        }
        
        self.cache.set(cache_key, decision, ttl)
    
    def get_reasoning_decision(self, stage: str, context_hash: str) -> Optional[Dict[str, Any]]:
        """Get cached reasoning decision"""
        cache_key = {
            "type": "reasoning_decision",
            "stage": stage,
            "context_hash": context_hash
        }
        
        return self.cache.get(cache_key)
    
    def invalidate_by_pattern(self, pattern: Dict[str, Any]) -> int:
        """Invalidate cache entries matching a pattern"""
        # This is a simplified implementation
        # In a production system, you might want more sophisticated pattern matching
        invalidated = 0
        
        # For now, just clear all entries of a specific type
        if "type" in pattern:
            # Would need to iterate through cache and match patterns
            # For simplicity, just clear all for now
            pass
        
        return invalidated
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return self.cache.get_stats()
    
    def cleanup(self) -> int:
        """Clean up expired entries"""
        return self.cache.cleanup_expired()
    
    def clear(self):
        """Clear all cache entries"""
        self.cache.clear()


# Global cache instance
_global_cache: Optional[ResponseCache] = None


def get_cache() -> ResponseCache:
    """Get global cache instance"""
    global _global_cache
    if _global_cache is None:
        _global_cache = ResponseCache()
    return _global_cache


def configure_cache(max_size: int = 500, default_ttl: int = 3600) -> ResponseCache:
    """Configure global cache"""
    global _global_cache
    _global_cache = ResponseCache(max_size, default_ttl)
    return _global_cache