from __future__ import annotations

from collections import defaultdict, deque
import hashlib
from time import monotonic

from fastapi import Request


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


def get_client_ip(request: Request, trust_forwarded_for: bool = False) -> str:
    if trust_forwarded_for:
        forwarded_for = request.headers.get("x-forwarded-for", "").strip()
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def allow_control_plane_request(
    bucket: str,
    request: Request,
    *,
    limit: int,
    window_seconds: int,
    licence_key: str | None = None,
    trust_forwarded_for: bool = False,
) -> bool:
    client_ip = get_client_ip(request, trust_forwarded_for=trust_forwarded_for)
    if not rate_limiter.allow(f"{bucket}:ip", client_ip, limit, window_seconds):
        return False

    if licence_key:
        if not rate_limiter.allow(
            f"{bucket}:licence",
            _fingerprint(licence_key),
            limit,
            window_seconds,
        ):
            return False

    return True
