"""Redis-backed rate limiting with a safe local fallback."""

from __future__ import annotations

import os
import time
from typing import Dict, Tuple


class RateLimiter:
    """Redis-backed rate limiter with an in-process fallback for tests."""

    def __init__(self, redis_url: str | None = None):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379")
        self._redis = None
        self._local_counts: Dict[str, Tuple[int, int]] = {}

    def _get_redis(self):
        if self._redis is not None:
            return self._redis if self._redis is not False else None

        try:
            import redis

            client = redis.from_url(self.redis_url, decode_responses=True)
            client.ping()
            self._redis = client
            return self._redis
        except Exception:
            self._redis = False
            return None

    def check_rate_limit(self, key: str, limit: int = 100, window: int = 60, fail_closed: bool = False) -> Tuple[bool, int]:
        current = int(time.time())
        window_key = f"ratelimit:{key}:{current // window}"

        redis_client = self._get_redis()
        if redis_client:
            count = int(redis_client.incr(window_key))
            redis_client.expire(window_key, window + 1)
            if count > limit:
                return False, 0
            return True, limit - count

        # If Redis is unavailable and fail_closed is True, reject the request.
        if fail_closed:
            return False, 0

        window_start, count = self._local_counts.get(window_key, (current, 0))
        if current - window_start >= window:
            window_start, count = current, 0

        count += 1
        self._local_counts[window_key] = (window_start, count)
        if count > limit:
            return False, 0
        return True, limit - count