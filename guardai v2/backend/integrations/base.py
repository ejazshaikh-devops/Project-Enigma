"""
GuardAI Backend — Threat Intelligence: Base Interface

Every provider (Google Safe Browsing, OpenPhish, PhishTank, future feeds)
implements this same async interface so the aggregator can call them
uniformly, run them concurrently, and degrade gracefully if one fails.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ThreatIntelHit:
    """A single piece of evidence from a threat intelligence source."""
    source: str                 # e.g. "Google Safe Browsing"
    threat: str                 # e.g. "SOCIAL_ENGINEERING", "phishing"
    confidence: int = 90        # 0-100
    detail: Optional[str] = None
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "threat": self.threat,
            "confidence": self.confidence,
            "detail": self.detail,
        }


class ThreatIntelProvider(ABC):
    """Abstract base class all threat intel integrations must implement."""

    name: str = "unknown"

    @abstractmethod
    async def check_url(self, url: str) -> list[ThreatIntelHit]:
        """
        Check a URL against this provider's data.
        MUST NOT raise on provider-side failure — catch internally and
        return an empty list; the circuit breaker / caller handles failure
        tracking via check_url_safe().
        """
        raise NotImplementedError

    async def health(self) -> dict:
        """Return a small status dict for the /health and /metrics endpoints."""
        return {"name": self.name, "status": "unknown"}
