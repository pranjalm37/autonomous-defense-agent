"""
Detection primitives: the Detection result, the BaseRule contract, and the
small toolkit of helpers (field access, grouping, sliding-window counting,
IP classification) that the rules share.

Design notes
------------
* A rule is *stateless* and *pure*: `evaluate(events) -> list[Detection]`. The
  engine owns persistence and event selection. This makes every rule trivially
  unit-testable with in-memory events and no database.
* Rules read fields through `field()` which looks in normalized_payload first,
  then raw_payload, then the ORM attribute — so a rule written against the
  canonical schema still works when an extra signal only exists in the raw blob.
"""
from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from collections import defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime

from app.models.alert import Severity


# ──────────────────────────────────────────────────────────────────────────────
# Result type
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class Detection:
    rule_id: str
    title: str
    description: str
    threat_type: str

    severity: Severity
    risk_score: int            # 0–100
    confidence: float          # 0.0–1.0

    mitre_tactics: list[str]
    mitre_techniques: list[str]

    source_ip: str | None = None
    dest_ip: str | None = None
    hostname: str | None = None
    affected_user: str | None = None

    evidence_event_ids: list = dc_field(default_factory=list)
    iocs: dict = dc_field(default_factory=dict)
    metadata: dict = dc_field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# Rule contract
# ──────────────────────────────────────────────────────────────────────────────
class BaseRule(ABC):
    rule_id: str = "base"
    name: str = "Base Rule"
    threat_type: str = "generic"

    def __init__(self, **threshold_overrides):
        # Subclasses declare thresholds as class attrs; allow per-instance tuning.
        for k, v in threshold_overrides.items():
            if hasattr(self, k):
                setattr(self, k, v)

    @abstractmethod
    def evaluate(self, events: Sequence) -> list[Detection]:
        """Return zero or more detections found in this event batch."""
        raise NotImplementedError


# ──────────────────────────────────────────────────────────────────────────────
# Field access
# ──────────────────────────────────────────────────────────────────────────────
def field(event, *keys, default=None):
    """First non-None value found across normalized_payload → raw_payload → attr."""
    np = getattr(event, "normalized_payload", None) or {}
    rp = getattr(event, "raw_payload", None) or {}
    for key in keys:
        for src in (np, rp):
            if isinstance(src, dict) and src.get(key) not in (None, "", "-"):
                return src[key]
        attr = getattr(event, key, None)
        if attr not in (None, "", "-"):
            return attr
    return default


def event_time(event) -> datetime:
    return getattr(event, "ingested_at", None) or getattr(event, "created_at", None)


# ──────────────────────────────────────────────────────────────────────────────
# Grouping & windowing
# ──────────────────────────────────────────────────────────────────────────────
def group_by(events: Iterable, keyfn: Callable) -> dict[object, list]:
    buckets: dict[object, list] = defaultdict(list)
    for e in events:
        k = keyfn(e)
        if k is not None:
            buckets[k].append(e)
    return dict(buckets)


def max_in_window(events: Sequence, window_seconds: int) -> tuple[int, list]:
    """
    Sliding-window peak: the largest number of events that fall within any
    `window_seconds`-wide window, plus the events in that peak window.

    This is the core of threshold detection — "N events in T seconds" — and is
    far more robust than counting per fixed calendar minute (which an attacker
    can dodge by straddling a minute boundary).
    """
    timed = sorted([e for e in events if event_time(e) is not None], key=event_time)
    if not timed:
        return 0, []
    best_count, best_slice = 0, []
    left = 0
    for right in range(len(timed)):
        while (event_time(timed[right]) - event_time(timed[left])).total_seconds() > window_seconds:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_slice = timed[left:right + 1]
    return best_count, best_slice


def distinct(events: Iterable, keyfn: Callable) -> set:
    return {k for k in (keyfn(e) for e in events) if k is not None}


# ──────────────────────────────────────────────────────────────────────────────
# IP helpers
# ──────────────────────────────────────────────────────────────────────────────
def is_external(ip: str | None) -> bool:
    """True for routable public addresses (the ones worth alerting hardest on)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)


def asset_factor_for(*, external_source: bool, hits_internal: bool) -> float:
    """External attacker hitting internal assets is the worst case."""
    if external_source and hits_internal:
        return 1.4
    if external_source:
        return 1.25
    return 1.0
