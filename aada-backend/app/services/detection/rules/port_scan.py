"""
Port Scan  —  MITRE T1046 (Discovery) / T1595 (Active Scanning)

Concept
-------
A scan probes many services to map the attack surface. Two shapes:

  - **Vertical scan**   — one source → one host, MANY ports  ("what's open here?")
  - **Horizontal scan** — one source → one port, MANY hosts  ("who runs SSH?")

Signature: high *fan-out cardinality* from a single source IP in a short window.
We count distinct (dest_ip, dest_port) pairs; either many ports on few hosts or
few ports across many hosts trips the rule. Connection-denied firewall/IDS events
are the richest input.
"""
from __future__ import annotations

from collections.abc import Sequence

from app.models.alert import Severity
from app.services.detection import mitre, scoring
from app.services.detection.base import (
    BaseRule, Detection, field, group_by, max_in_window, distinct, is_external,
)


class PortScanRule(BaseRule):
    rule_id = "port_scan"
    name = "Port / Network Scan"
    threat_type = "reconnaissance"

    # ── Tunable thresholds ──
    DISTINCT_PORT_THRESHOLD = 15   # vertical scan
    DISTINCT_HOST_THRESHOLD = 10   # horizontal scan
    WINDOW_SECONDS = 60

    def evaluate(self, events: Sequence) -> list[Detection]:
        # Connection-oriented events that carry a destination port.
        conn = [e for e in events if field(e, "dest_port") is not None and field(e, "source_ip")]
        detections: list[Detection] = []

        for src_ip, ip_events in group_by(conn, lambda e: field(e, "source_ip")).items():
            peak, window_events = max_in_window(ip_events, self.WINDOW_SECONDS)
            if not window_events:
                continue

            ports = distinct(window_events, lambda e: field(e, "dest_port"))
            hosts = distinct(window_events, lambda e: field(e, "dest_ip"))
            vertical = len(ports) >= self.DISTINCT_PORT_THRESHOLD
            horizontal = len(hosts) >= self.DISTINCT_HOST_THRESHOLD
            if not (vertical or horizontal):
                continue

            scan_type = "vertical" if vertical and not horizontal else \
                        "horizontal" if horizontal and not vertical else "block"
            spread = max(len(ports), len(hosts))
            threshold = self.DISTINCT_PORT_THRESHOLD if vertical else self.DISTINCT_HOST_THRESHOLD
            external = is_external(src_ip)

            confidence = min(0.9, 0.55 + 0.02 * (spread - threshold))
            base_sev = Severity.MEDIUM   # recon is rarely critical on its own
            score = scoring.compute_risk_score(
                base_sev, confidence,
                volume_factor=scoring.over_threshold_factor(spread, threshold, saturation=threshold * 6),
                asset_factor=1.25 if external else 0.9,
            )

            detections.append(Detection(
                rule_id=self.rule_id,
                title=f"{scan_type.capitalize()} port scan from {src_ip} "
                      f"({len(ports)} ports / {len(hosts)} hosts)",
                description=(
                    f"{src_ip} touched {len(ports)} distinct ports across {len(hosts)} host(s) "
                    f"in {self.WINDOW_SECONDS}s — consistent with a {scan_type} network scan."
                ),
                threat_type=self.threat_type,
                severity=scoring.severity_from_score(score),
                risk_score=score,
                confidence=round(confidence, 2),
                mitre_techniques=["T1046", "T1595"],
                mitre_tactics=mitre.tactics_for("T1046", "T1595"),
                source_ip=src_ip,
                dest_ip=sorted(hosts)[0] if len(hosts) == 1 else None,
                evidence_event_ids=[getattr(e, "id", None) for e in window_events],
                iocs={"source_ip": src_ip, "scanned_ports": sorted(ports)[:50]},
                metadata={
                    "scan_type": scan_type,
                    "distinct_ports": len(ports),
                    "distinct_hosts": len(hosts),
                    "window_seconds": self.WINDOW_SECONDS,
                },
            ))
        return detections
