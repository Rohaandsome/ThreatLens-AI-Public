"""In-memory sliding-window rate limiter (local MVP, single process).

Buckets are keyed by authenticated session token (per-user limits) with a
per-IP fallback for unauthenticated callers. Enforcement lives in route
dependencies declared AFTER authentication, so anonymous callers still get
401s while floods from any source get 429s with Retry-After. State drops on
restart alongside sessions; tests reset via clear_rate_state().
"""

import math
import threading
import time
from collections import deque
from dataclasses import dataclass

from fastapi import Request

from ..errors import AnalysisError
from . import authz


@dataclass(frozen=True)
class Bucket:
    max_requests: int
    window_seconds: float


BUCKETS = {
    # Paid Meta Model API spend: a human analyzes a handful of reports/hour.
    "analyze": Bucket(10, 3600.0),
    # Externally visible MISP writes (drafts + publishes).
    "misp_write": Bucket(20, 3600.0),
    # MISP connection checks + local previews.
    "misp_read": Bucket(60, 3600.0),
    # CPU/memory-heavy rendering: prepare, PDF/STIX exports.
    "share": Bucket(60, 3600.0),
}

_lock = threading.Lock()
_hits: dict[tuple[str, str], deque[float]] = {}


def clear_rate_state() -> None:
    """Drop all counters (tests only)."""
    with _lock:
        _hits.clear()


def _identity(request: Request) -> str:
    """Session token when present, else client IP. Server-side only."""
    token = request.cookies.get(authz.SESSION_COOKIE)
    if token:
        return f"session:{token}"
    host = request.client.host if request.client else "unknown"
    return f"ip:{host}"


def check(bucket: str, request: Request) -> None:
    """Record a hit or raise 429 with Retry-After. Safe message only."""
    spec = BUCKETS[bucket]
    key = (bucket, _identity(request))
    now = time.monotonic()
    with _lock:
        hits = _hits.setdefault(key, deque())
        cutoff = now - spec.window_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()
        if len(hits) >= spec.max_requests:
            retry_after = max(1, math.ceil(spec.window_seconds - (now - hits[0])))
            raise AnalysisError(
                429,
                "rate_limited",
                "Too many requests. Retry in "
                f"{retry_after} second{'s' if retry_after != 1 else ''}.",
                retry_after=str(retry_after),
            )
        hits.append(now)
        if len(_hits) > 4096:
            for stale in [k for k, v in _hits.items() if not v]:
                del _hits[stale]


def limited(bucket: str):
    """FastAPI dependency factory enforcing a named bucket."""

    def dependency(request: Request) -> None:
        check(bucket, request)

    return dependency
