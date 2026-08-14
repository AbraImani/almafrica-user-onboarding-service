"""Small thread-safe in-memory rate limiter."""

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock


@dataclass(frozen=True)
class RateLimitDecision:
    """Result of consuming one rate-limit allowance."""

    allowed: bool
    retry_after_seconds: int = 0


class InMemoryRateLimiter:
    """Sliding-window limiter scoped to one application process."""

    def __init__(self, *, limit: int, window_seconds: int) -> None:
        if limit < 1 or window_seconds < 1:
            raise ValueError("Rate limit and window must be positive")
        self._limit = limit
        self._window_seconds = window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()
        self._last_cleanup = 0.0

    def check(self, key: str, *, now: float | None = None) -> RateLimitDecision:
        """Consume one allowance for a key or return its retry delay."""
        checked_at = time.monotonic() if now is None else now
        cutoff = checked_at - self._window_seconds

        with self._lock:
            self._cleanup(cutoff, checked_at)
            attempts = self._attempts[key]
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()

            if len(attempts) >= self._limit:
                retry_after = max(
                    1,
                    math.ceil(attempts[0] + self._window_seconds - checked_at),
                )
                return RateLimitDecision(
                    allowed=False,
                    retry_after_seconds=retry_after,
                )

            attempts.append(checked_at)
            return RateLimitDecision(allowed=True)

    def _cleanup(self, cutoff: float, checked_at: float) -> None:
        """Periodically discard inactive keys so memory does not grow forever."""
        if checked_at - self._last_cleanup < self._window_seconds:
            return
        for key, attempts in list(self._attempts.items()):
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            if not attempts:
                del self._attempts[key]
        self._last_cleanup = checked_at
