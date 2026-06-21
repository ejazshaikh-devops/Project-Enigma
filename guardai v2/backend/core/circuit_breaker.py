"""
GuardAI Backend — Circuit Breaker

A minimal async-safe circuit breaker. After N consecutive failures, the
breaker "opens" and short-circuits calls for a recovery window, preventing
the backend from hammering (or waiting on) a degraded upstream provider.

States: CLOSED (normal) → OPEN (failing, short-circuit) → HALF_OPEN (probe) → CLOSED
"""

import time
import asyncio
import logging
from enum import Enum

logger = logging.getLogger("guardai.circuit_breaker")


class CircuitState(str, Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(self, name: str, failure_threshold: int = 3, recovery_seconds: int = 60):
        self.name              = name
        self.failure_threshold = failure_threshold
        self.recovery_seconds  = recovery_seconds
        self._failures         = 0
        self._opened_at: float | None = None
        self._lock              = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        if self._opened_at is None:
            return CircuitState.CLOSED
        if time.monotonic() - self._opened_at >= self.recovery_seconds:
            return CircuitState.HALF_OPEN
        return CircuitState.OPEN

    async def allow_request(self) -> bool:
        async with self._lock:
            state = self.state
            if state == CircuitState.OPEN:
                return False
            return True

    async def record_success(self) -> None:
        async with self._lock:
            if self._failures > 0 or self._opened_at is not None:
                logger.info("Circuit breaker '%s' recovered — closing.", self.name)
            self._failures  = 0
            self._opened_at = None

    async def record_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold and self._opened_at is None:
                self._opened_at = time.monotonic()
                logger.warning(
                    "Circuit breaker '%s' OPENED after %d failures — cooling down for %ds",
                    self.name, self._failures, self.recovery_seconds,
                )

    def status(self) -> dict:
        return {
            "name":     self.name,
            "state":    self.state.value,
            "failures": self._failures,
        }
