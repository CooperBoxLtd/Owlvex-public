from __future__ import annotations

from collections import defaultdict, deque
from time import monotonic


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, dict[str, deque[float]]] = defaultdict(lambda: defaultdict(deque))

    def allow(self, bucket: str, key: str, limit: int, window_seconds: int) -> bool:
        now = monotonic()
        bucket_store = self._buckets[bucket]
        entries = bucket_store[key]
        cutoff = now - window_seconds

        while entries and entries[0] <= cutoff:
            entries.popleft()

        if len(entries) >= limit:
            return False

        entries.append(now)
        return True

    def clear(self) -> None:
        self._buckets.clear()


rate_limiter = InMemoryRateLimiter()


def clear_rate_limit_state() -> None:
    rate_limiter.clear()
