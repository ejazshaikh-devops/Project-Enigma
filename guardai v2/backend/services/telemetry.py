"""
GuardAI Backend — Privacy-Preserving Telemetry Service

CRITICAL PRIVACY GUARANTEE: this module NEVER stores URLs, IP addresses,
hostnames, or any per-request identifying information. Only aggregate
counters are kept, satisfying the "no browsing history collection"
requirement from the product privacy policy.

In-process counters reset on restart. For durable cross-instance metrics,
back this with Redis INCR or a managed metrics service (CloudWatch custom
metrics) — see ARCHITECTURE.md for the recommended production design.
"""

import time
import logging
from collections import defaultdict
from threading import Lock

logger = logging.getLogger("guardai.services.telemetry")

_lock = Lock()
_start_time = time.time()

_counters = {
    "scans_total": 0,
    "threats_blocked": 0,
    "verdict_distribution": defaultdict(int),
    "api_latency_samples": [],   # capped list of recent latencies (ms)
    "extension_versions": defaultdict(int),
}

_MAX_LATENCY_SAMPLES = 1000


def record_scan(verdict: str) -> None:
    with _lock:
        _counters["scans_total"] += 1
        _counters["verdict_distribution"][verdict] += 1
        if verdict == "dangerous":
            _counters["threats_blocked"] += 1


def record_latency(ms: float) -> None:
    with _lock:
        samples = _counters["api_latency_samples"]
        samples.append(ms)
        if len(samples) > _MAX_LATENCY_SAMPLES:
            del samples[: len(samples) - _MAX_LATENCY_SAMPLES]


def record_extension_version(version: str) -> None:
    if not version or len(version) > 20:
        return
    with _lock:
        _counters["extension_versions"][version] += 1


def get_snapshot() -> dict:
    with _lock:
        samples = _counters["api_latency_samples"]
        avg_latency = round(sum(samples) / len(samples), 1) if samples else 0.0
        p95_latency = 0.0
        if samples:
            sorted_samples = sorted(samples)
            idx = max(0, int(len(sorted_samples) * 0.95) - 1)
            p95_latency = round(sorted_samples[idx], 1)

        return {
            "scans_total": _counters["scans_total"],
            "threats_blocked": _counters["threats_blocked"],
            "verdict_distribution": dict(_counters["verdict_distribution"]),
            "extension_versions": dict(_counters["extension_versions"]),
            "api_latency_ms": {
                "avg": avg_latency,
                "p95": p95_latency,
                "sample_count": len(samples),
            },
            "uptime_seconds": round(time.time() - _start_time, 1),
        }
