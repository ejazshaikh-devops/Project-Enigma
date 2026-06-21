"""
GuardAI Backend — Pydantic Models

Strict input validation is a critical security control: the /analyze
endpoint accepts arbitrary URLs from an extension that could be modified
or spoofed by an attacker, so every field is bounded and type-checked.
"""

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)
    local_score: Optional[float] = Field(default=None, ge=0, le=1)
    local_flags: Optional[list[str]] = Field(default=None, max_length=50)
    timestamp: Optional[int] = None

    @field_validator("url")
    @classmethod
    def validate_url_scheme(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("url must start with http:// or https://")
        # Reject control characters / null bytes defensively
        if any(ord(c) < 0x20 for c in v):
            raise ValueError("url contains invalid control characters")
        return v

    @field_validator("local_flags")
    @classmethod
    def validate_flags(cls, v):
        if v is None:
            return v
        return [str(flag)[:120] for flag in v[:50]]


class ThreatIntelHitResponse(BaseModel):
    source: str
    threat: str
    confidence: int
    detail: Optional[str] = None


class BrandHitResponse(BaseModel):
    type: str
    brand: str
    confidence: int
    evidence: str


class AnalyzeResponse(BaseModel):
    verdict: str                       # safe | suspicious | dangerous
    confidence: int                    # 0-100
    risk_score: float                  # 0.0-1.0, canonical score
    reasons: list[str]
    triggered_rules: list[str]
    ai_score: Optional[int] = None
    threat_intel: list[ThreatIntelHitResponse] = Field(default_factory=list)
    brand_hits: list[BrandHitResponse] = Field(default_factory=list)
    request_id: Optional[str] = None
