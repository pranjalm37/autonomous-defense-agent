"""
Attack-simulator tests.

The scenario generators must produce data that the *real* parsers and detection
rules react to, so these assert on the pipeline's behaviour rather than on the
generated strings.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from app.schemas.event import LogFormat
from app.services.detection.engine import DetectionEngine
from app.services.ingestion.normalizer import normalize
from app.services.ingestion.parsers import get_parser
from app.services.simulator.scenarios import SCENARIOS


def _pipeline(scenario) -> list:
    """Parse + normalize a scenario exactly as ingestion would, without a DB."""
    raw = scenario.generate()
    content = json.dumps(raw) if scenario.fmt is LogFormat.JSON else (
        raw if isinstance(raw, str) else "\n".join(raw)
    )
    parser = get_parser(scenario.fmt)
    return [normalize(p, default_source=parser.default_source) for p in parser.parse(content)]


def test_registry_is_well_formed():
    assert SCENARIOS, "at least one scenario must be registered"
    for sid, s in SCENARIOS.items():
        assert s.id == sid
        assert s.name and s.description and s.mitre
        assert isinstance(s.fmt, LogFormat)
        assert s.expected_rule


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
def test_scenario_parses_and_normalizes(scenario_id):
    events = _pipeline(SCENARIOS[scenario_id])
    assert events, f"{scenario_id} produced no parseable events"


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
def test_scenario_timestamps_are_recent(scenario_id):
    """Detection works over a lookback window, so staged events must be 'now'."""
    events = _pipeline(SCENARIOS[scenario_id])
    now = datetime.now(timezone.utc)
    for e in events:
        ts = getattr(e, "timestamp", None) or getattr(e, "event_time", None)
        if ts is None:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        age = (now - ts).total_seconds()
        assert -60 < age < 3600, f"{scenario_id} event is {age:.0f}s from now"


@pytest.mark.parametrize("scenario_id", sorted(SCENARIOS))
def test_scenario_trips_its_expected_rule(scenario_id):
    scenario = SCENARIOS[scenario_id]
    detections = DetectionEngine().analyze(_pipeline(scenario))
    fired = {d.rule_id for d in detections}
    assert scenario.expected_rule in fired, (
        f"{scenario_id} expected rule '{scenario.expected_rule}', got {sorted(fired) or 'none'}"
    )
