"""
Impossible Travel  —  MITRE T1078 (Valid Accounts)

Concept
-------
A classic UEBA (User & Entity Behavior Analytics) detection. If a single account
authenticates successfully from two locations whose separation would require
travel faster than any plausible human movement, one of those sessions is almost
certainly an attacker using valid (stolen) credentials.

    required_speed = distance_km / elapsed_hours
    if required_speed > MAX_SPEED_KMH  →  impossible travel

MAX_SPEED_KMH defaults to 900 (≈ cruising speed of a commercial jet). We compare
*consecutive successful logins* per user, skipping internal/un-geolocatable IPs.
The same login from one IP, or two logins from the same city, never fires.
"""
from __future__ import annotations

from collections.abc import Sequence

from app.models.alert import Severity
from app.services.detection import mitre, scoring
from app.services.detection.base import BaseRule, Detection, event_time, field, group_by
from app.services.detection.geo import GeoResolver, StaticGeoResolver, haversine_km

_SUCCESS_EVENTS = {"ssh_login_success", "login_success", "console_login"}


def _is_success(e) -> bool:
    et = field(e, "event_type")
    if et in _SUCCESS_EVENTS:
        return True
    if et == "http_request":
        try:
            return int(field(e, "status_code", default=0)) in (200, 302) and bool(field(e, "username"))
        except (TypeError, ValueError):
            return False
    return False


class ImpossibleTravelRule(BaseRule):
    rule_id = "impossible_travel"
    name = "Impossible Travel"
    threat_type = "account_takeover"

    # ── Tunable thresholds ──
    MAX_SPEED_KMH = 900.0
    MIN_DISTANCE_KM = 500.0   # ignore short hops (geo-IP jitter near a city)

    def __init__(self, geo: GeoResolver | None = None, **overrides):
        super().__init__(**overrides)
        self.geo = geo or StaticGeoResolver()

    def evaluate(self, events: Sequence) -> list[Detection]:
        logins = [e for e in events if _is_success(e) and field(e, "username") and field(e, "source_ip")]
        detections: list[Detection] = []

        for user, user_events in group_by(logins, lambda e: field(e, "username")).items():
            timeline = sorted(user_events, key=event_time)
            for prev, cur in zip(timeline, timeline[1:]):
                ip_a, ip_b = field(prev, "source_ip"), field(cur, "source_ip")
                if ip_a == ip_b:
                    continue
                pa, pb = self.geo.resolve(ip_a), self.geo.resolve(ip_b)
                if pa is None or pb is None:
                    continue

                distance = haversine_km(pa, pb)
                hours = max((event_time(cur) - event_time(prev)).total_seconds() / 3600.0, 1e-6)
                speed = distance / hours
                if distance < self.MIN_DISTANCE_KM or speed <= self.MAX_SPEED_KMH:
                    continue

                # Confidence rises the more absurd the implied speed is.
                confidence = min(0.97, 0.7 + 0.1 * min((speed / self.MAX_SPEED_KMH) - 1, 2.5))
                score = scoring.compute_risk_score(
                    Severity.HIGH, confidence,
                    volume_factor=min((speed / self.MAX_SPEED_KMH) / 5, 1.0),
                    asset_factor=1.3,
                    escalation_bonus=10.0,
                )

                detections.append(Detection(
                    rule_id=self.rule_id,
                    title=f"Impossible travel for '{user}': "
                          f"{pa.city or ip_a} → {pb.city or ip_b}",
                    description=(
                        f"User '{user}' logged in from {ip_a} ({pa.city}, {pa.country}) then "
                        f"{ip_b} ({pb.city}, {pb.country}) — {distance:.0f} km apart in "
                        f"{hours:.2f} h, implying {speed:.0f} km/h (> {self.MAX_SPEED_KMH:.0f} km/h). "
                        "One session is likely an attacker with valid credentials."
                    ),
                    threat_type=self.threat_type,
                    severity=scoring.severity_from_score(score),
                    risk_score=score,
                    confidence=round(confidence, 2),
                    mitre_techniques=["T1078"],
                    mitre_tactics=mitre.tactics_for("T1078"),
                    source_ip=ip_b,
                    affected_user=user,
                    evidence_event_ids=[getattr(prev, "id", None), getattr(cur, "id", None)],
                    iocs={"source_ips": [ip_a, ip_b], "countries": [pa.country, pb.country]},
                    metadata={
                        "distance_km": round(distance),
                        "elapsed_hours": round(hours, 2),
                        "implied_speed_kmh": round(speed),
                        "from": {"ip": ip_a, "city": pa.city, "country": pa.country},
                        "to": {"ip": ip_b, "city": pb.city, "country": pb.country},
                    },
                ))
        return detections
