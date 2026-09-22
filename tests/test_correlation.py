"""Tests for the alert correlation engine.

Covers: time-window grouping, attack chain detection, statistical clustering,
incident merging, severity escalation, and title generation.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from soc_analyzer.correlation.engine import CorrelationEngine
from soc_analyzer.correlation.incidents import (
    AttackStage,
    Incident,
    IncidentSeverity,
)
from soc_analyzer.correlation.strategies import (
    AttackChainCorrelator,
    StatisticalCorrelator,
    TimeWindowCorrelator,
)
from soc_analyzer.models.schemas import (
    AttackCategory,
    LogSource,
    NormalizedLogEvent,
    SeverityLevel,
)


def _make_event(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "192.168.1.1",
    dst_port: int = 22,
    severity: SeverityLevel = SeverityLevel.MEDIUM,
    attack_category: AttackCategory = AttackCategory.BRUTE_FORCE,
    timestamp: datetime | None = None,
    **kwargs,
) -> NormalizedLogEvent:
    """Helper to create test events."""
    return NormalizedLogEvent(
        timestamp=timestamp or datetime.now(),
        source_type=LogSource.AUTH,
        severity=severity,
        attack_category=attack_category,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="TCP",
        action="deny",
        event_name=f"Test event {attack_category.value}",
        **kwargs,
    )


class TestIncident:
    """Test the Incident data model."""

    def test_add_event_updates_timeline(self) -> None:
        incident = Incident()
        t1 = datetime(2024, 1, 1, 10, 0, 0)
        t2 = datetime(2024, 1, 1, 10, 5, 0)

        incident.add_event(_make_event(timestamp=t1))
        incident.add_event(_make_event(timestamp=t2))

        assert incident.first_seen == t1
        assert incident.last_seen == t2
        assert incident.event_count == 2
        assert incident.duration_seconds == 300.0

    def test_add_event_tracks_ips(self) -> None:
        incident = Incident()
        incident.add_event(_make_event(src_ip="1.1.1.1", dst_ip="10.0.0.1"))
        incident.add_event(_make_event(src_ip="1.1.1.1", dst_ip="10.0.0.2"))
        incident.add_event(_make_event(src_ip="2.2.2.2", dst_ip="10.0.0.1"))

        assert len(incident.source_ips) == 2
        assert len(incident.destination_ips) == 2

    def test_severity_escalation_critical(self) -> None:
        incident = Incident()
        incident.add_event(_make_event(severity=SeverityLevel.CRITICAL))
        assert incident.severity == IncidentSeverity.CRITICAL

    def test_severity_escalation_multiple_high(self) -> None:
        incident = Incident()
        for _ in range(3):
            incident.add_event(_make_event(severity=SeverityLevel.HIGH))
        assert incident.severity == IncidentSeverity.CRITICAL

    def test_severity_escalation_multi_stage(self) -> None:
        """Multi-stage attack chains should escalate severity."""
        incident = Incident()
        incident.add_event(_make_event(
            attack_category=AttackCategory.PORT_SCAN,
            severity=SeverityLevel.MEDIUM,
        ))
        incident.add_event(_make_event(
            attack_category=AttackCategory.BRUTE_FORCE,
            severity=SeverityLevel.MEDIUM,
        ))
        # recon + initial_access = 2 stages → medium escalates to high
        assert incident.severity == IncidentSeverity.HIGH

    def test_generate_title(self) -> None:
        incident = Incident()
        incident.add_event(_make_event(
            src_ip="91.240.118.172",
            dst_ip="10.0.0.5",
            attack_category=AttackCategory.BRUTE_FORCE,
        ))
        title = incident.generate_title()
        assert "Brute Force" in title
        assert "91.240.118.172" in title

    def test_events_per_minute(self) -> None:
        incident = Incident()
        base = datetime(2024, 1, 1, 10, 0, 0)
        for i in range(60):
            incident.add_event(_make_event(timestamp=base + timedelta(seconds=i * 2)))
        assert incident.events_per_minute == pytest.approx(30.0, abs=1.0)

    def test_sample_events_capped(self) -> None:
        incident = Incident()
        for i in range(20):
            incident.add_event(_make_event())
        assert len(incident.sample_events) == 5  # Capped at 5


class TestTimeWindowCorrelator:
    """Test time-window based correlation."""

    def test_groups_same_ip_in_window(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            _make_event(src_ip="1.1.1.1", timestamp=base + timedelta(seconds=i * 10))
            for i in range(10)
        ]
        correlator = TimeWindowCorrelator(window_seconds=300, min_events=3)
        incidents = correlator.correlate(events)
        assert len(incidents) == 1
        assert incidents[0].event_count == 10

    def test_splits_on_time_gap(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            # Group 1: 5 events in first 2 minutes
            *[_make_event(src_ip="1.1.1.1", timestamp=base + timedelta(seconds=i * 20))
              for i in range(5)],
            # Group 2: 5 events starting 10 minutes later
            *[_make_event(src_ip="1.1.1.1", timestamp=base + timedelta(minutes=10, seconds=i * 20))
              for i in range(5)],
        ]
        correlator = TimeWindowCorrelator(window_seconds=300, min_events=3)
        incidents = correlator.correlate(events)
        assert len(incidents) == 2

    def test_different_ips_separate_incidents(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            *[_make_event(src_ip="1.1.1.1", timestamp=base + timedelta(seconds=i * 10))
              for i in range(5)],
            *[_make_event(src_ip="2.2.2.2", timestamp=base + timedelta(seconds=i * 10))
              for i in range(5)],
        ]
        correlator = TimeWindowCorrelator(window_seconds=300, min_events=3)
        incidents = correlator.correlate(events)
        assert len(incidents) == 2

    def test_min_events_threshold(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            _make_event(src_ip="1.1.1.1", timestamp=base + timedelta(seconds=i))
            for i in range(2)  # Only 2 events — below threshold
        ]
        correlator = TimeWindowCorrelator(window_seconds=300, min_events=3)
        incidents = correlator.correlate(events)
        assert len(incidents) == 0

    def test_benign_events_filtered(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            _make_event(
                src_ip="1.1.1.1",
                severity=SeverityLevel.BENIGN,
                timestamp=base + timedelta(seconds=i),
            )
            for i in range(10)
        ]
        correlator = TimeWindowCorrelator(window_seconds=300, min_events=3)
        incidents = correlator.correlate(events)
        assert len(incidents) == 0


class TestAttackChainCorrelator:
    """Test attack chain detection."""

    def test_detects_two_stage_chain(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            _make_event(
                src_ip="1.1.1.1",
                attack_category=AttackCategory.PORT_SCAN,
                severity=SeverityLevel.MEDIUM,
                timestamp=base,
            ),
            _make_event(
                src_ip="1.1.1.1",
                attack_category=AttackCategory.BRUTE_FORCE,
                severity=SeverityLevel.HIGH,
                timestamp=base + timedelta(minutes=5),
            ),
        ]
        correlator = AttackChainCorrelator(window_seconds=3600, min_stages=2)
        incidents = correlator.correlate(events)
        assert len(incidents) == 1
        assert "reconnaissance" in incidents[0].attack_stages
        assert "initial_access" in incidents[0].attack_stages

    def test_no_chain_single_stage(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            _make_event(
                src_ip="1.1.1.1",
                attack_category=AttackCategory.PORT_SCAN,
                severity=SeverityLevel.MEDIUM,
                timestamp=base + timedelta(seconds=i),
            )
            for i in range(5)  # All same stage
        ]
        correlator = AttackChainCorrelator(window_seconds=3600, min_stages=2)
        incidents = correlator.correlate(events)
        assert len(incidents) == 0

    def test_chain_generates_title_with_stages(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            _make_event(src_ip="1.1.1.1", attack_category=AttackCategory.PORT_SCAN,
                        severity=SeverityLevel.MEDIUM, timestamp=base),
            _make_event(src_ip="1.1.1.1", attack_category=AttackCategory.BRUTE_FORCE,
                        severity=SeverityLevel.HIGH, timestamp=base + timedelta(minutes=5)),
            _make_event(src_ip="1.1.1.1", attack_category=AttackCategory.INFILTRATION,
                        severity=SeverityLevel.CRITICAL, timestamp=base + timedelta(minutes=15)),
        ]
        correlator = AttackChainCorrelator(window_seconds=3600, min_stages=2)
        incidents = correlator.correlate(events)
        assert len(incidents) == 1
        assert "multi-stage" in incidents[0].title


class TestStatisticalCorrelator:
    """Test DBSCAN-based statistical correlation."""

    def test_clusters_similar_events(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        # Create a tight cluster of similar events
        events = [
            _make_event(
                src_ip="1.1.1.1",
                dst_port=22,
                severity=SeverityLevel.MEDIUM,
                timestamp=base + timedelta(seconds=i),
                bytes_in=1000 + i * 10,
                bytes_out=500 + i * 5,
            )
            for i in range(20)
        ]
        correlator = StatisticalCorrelator(eps=1.0, min_samples=5)
        incidents = correlator.correlate(events)
        # Should find at least one cluster
        assert len(incidents) >= 1

    def test_no_clusters_diverse_events(self) -> None:
        import random
        random.seed(42)
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            _make_event(
                dst_port=random.choice([22, 80, 443, 3306, 8080, 3389, 5432]),
                severity=SeverityLevel.MEDIUM,
                timestamp=base + timedelta(seconds=i),
                bytes_in=random.randint(0, 1_000_000),
                bytes_out=random.randint(0, 1_000_000),
            )
            for i in range(10)
        ]
        correlator = StatisticalCorrelator(eps=0.3, min_samples=5)
        incidents = correlator.correlate(events)
        # With very diverse data and tight eps, expect few or no clusters
        assert len(incidents) <= 2


class TestCorrelationEngine:
    """Test the full correlation engine."""

    def _build_attack_scenario(self) -> list[NormalizedLogEvent]:
        """Build a realistic attack scenario for testing.

        Scenario: Attacker 91.240.118.172 performs:
            1. Port scan (10 events)
            2. SSH brute force (20 events)
            3. Successful infiltration (2 events)
        Plus background benign traffic (30 events)
        """
        base = datetime(2024, 1, 1, 10, 0, 0)
        events: list[NormalizedLogEvent] = []

        # Phase 1: Port scan
        for i in range(10):
            events.append(_make_event(
                src_ip="91.240.118.172",
                dst_port=22 + i,
                severity=SeverityLevel.MEDIUM,
                attack_category=AttackCategory.PORT_SCAN,
                timestamp=base + timedelta(seconds=i * 5),
            ))

        # Phase 2: Brute force (starts 2 min after scan)
        for i in range(20):
            events.append(_make_event(
                src_ip="91.240.118.172",
                dst_port=22,
                severity=SeverityLevel.HIGH,
                attack_category=AttackCategory.BRUTE_FORCE,
                timestamp=base + timedelta(minutes=2, seconds=i * 3),
            ))

        # Phase 3: Infiltration (5 min after brute force)
        for i in range(2):
            events.append(_make_event(
                src_ip="91.240.118.172",
                dst_port=22,
                severity=SeverityLevel.CRITICAL,
                attack_category=AttackCategory.INFILTRATION,
                timestamp=base + timedelta(minutes=7, seconds=i * 10),
            ))

        # Background benign traffic
        for i in range(30):
            events.append(_make_event(
                src_ip=f"10.0.0.{i % 10 + 1}",
                dst_port=80,
                severity=SeverityLevel.BENIGN,
                attack_category=AttackCategory.BENIGN,
                timestamp=base + timedelta(seconds=i * 30),
            ))

        return events

    def test_full_correlation(self) -> None:
        events = self._build_attack_scenario()
        engine = CorrelationEngine()
        incidents = engine.correlate(events)
        assert len(incidents) >= 1

    def test_critical_incidents_detected(self) -> None:
        events = self._build_attack_scenario()
        engine = CorrelationEngine()
        engine.correlate(events)
        critical = engine.get_critical_incidents()
        assert len(critical) >= 1
        assert all(
            i.severity in (IncidentSeverity.CRITICAL, IncidentSeverity.HIGH)
            for i in critical
        )

    def test_attacker_ip_in_incidents(self) -> None:
        events = self._build_attack_scenario()
        engine = CorrelationEngine()
        incidents = engine.correlate(events)
        attacker_incidents = [
            i for i in incidents if "91.240.118.172" in i.source_ips
        ]
        assert len(attacker_incidents) >= 1

    def test_stats_populated(self) -> None:
        events = self._build_attack_scenario()
        engine = CorrelationEngine()
        engine.correlate(events)
        stats = engine.get_stats()
        assert stats["total_events"] == len(events)
        assert stats["total_incidents_post_merge"] >= 1
        assert "by_strategy" in stats

    def test_event_ids_assigned(self) -> None:
        events = self._build_attack_scenario()
        engine = CorrelationEngine()
        engine.correlate(events)
        correlated_events = [e for e in events if e.incident_id is not None]
        assert len(correlated_events) > 0

    def test_empty_events(self) -> None:
        engine = CorrelationEngine()
        incidents = engine.correlate([])
        assert incidents == []

    def test_all_benign_no_incidents(self) -> None:
        base = datetime(2024, 1, 1, 10, 0, 0)
        events = [
            _make_event(
                severity=SeverityLevel.BENIGN,
                attack_category=AttackCategory.BENIGN,
                timestamp=base + timedelta(seconds=i),
            )
            for i in range(50)
        ]
        engine = CorrelationEngine()
        incidents = engine.correlate(events)
        # All strategies should filter out benign events
        assert len(incidents) == 0
