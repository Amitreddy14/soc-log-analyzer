"""Correlation strategies for grouping related security events.

Three complementary strategies, each catching what the others miss:

1. TimeWindowCorrelator
    Groups events from the same source IP within a sliding time window.
    Catches: brute force bursts, port scans, DDoS floods.
    Think: "50 failed SSH logins from the same IP in 2 minutes = 1 incident"

2. AttackChainCorrelator
    Detects multi-stage attack patterns by looking for sequences of
    attack categories that match known kill chain progressions.
    Catches: scan → exploit → persistence chains.
    Think: "port scan → brute force → successful login = coordinated attack"

3. StatisticalCorrelator
    Uses DBSCAN clustering on event feature vectors to find events
    that are statistically similar but don't match predefined rules.
    Catches: novel attack patterns, zero-days, low-and-slow attacks.
    Think: "these 20 events don't match any rule but they're abnormally similar"

Each strategy produces Incident objects independently. The CorrelationEngine
merges overlapping incidents from different strategies.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import numpy as np

from soc_analyzer.correlation.incidents import (
    CATEGORY_TO_STAGE,
    AttackStage,
    Incident,
    IncidentSeverity,
)
from soc_analyzer.models.schemas import AttackCategory, NormalizedLogEvent, SeverityLevel
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)


class BaseCorrelator(ABC):
    """Abstract base for correlation strategies."""

    name: str = "base"

    @abstractmethod
    def correlate(self, events: list[NormalizedLogEvent]) -> list[Incident]:
        """Analyze events and return correlated incidents."""
        ...


class TimeWindowCorrelator(BaseCorrelator):
    """Groups events from the same source IP within a time window.

    This is the most fundamental correlation — if the same IP generates
    multiple alerts within a short window, they're almost certainly related.

    Parameters:
        window_seconds: Maximum gap between events to be grouped (default 300 = 5 min)
        min_events: Minimum events to form an incident (default 3)
        severity_filter: Only correlate events at or above this severity
    """

    name = "time_window"

    def __init__(
        self,
        window_seconds: int = 300,
        min_events: int = 3,
        severity_filter: SeverityLevel = SeverityLevel.LOW,
    ) -> None:
        self.window_seconds = window_seconds
        self.min_events = min_events
        self.severity_filter = severity_filter
        self._severity_order = {
            SeverityLevel.BENIGN: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }

    def correlate(self, events: list[NormalizedLogEvent]) -> list[Incident]:
        """Group events by source IP within time windows."""
        # Filter to relevant events
        min_level = self._severity_order.get(self.severity_filter, 0)
        filtered = [
            e for e in events
            if self._severity_order.get(e.severity, 0) >= min_level
            and e.src_ip  # Must have a source IP
        ]

        if not filtered:
            return []

        # Group by source IP
        ip_groups: dict[str, list[NormalizedLogEvent]] = defaultdict(list)
        for event in filtered:
            ip_groups[event.src_ip].append(event)

        incidents = []
        for src_ip, ip_events in ip_groups.items():
            # Sort by timestamp
            ip_events.sort(key=lambda e: e.timestamp)

            # Sliding window grouping
            groups = self._window_group(ip_events)
            for group in groups:
                if len(group) >= self.min_events:
                    incident = Incident(correlation_rule=self.name)
                    for event in group:
                        incident.add_event(event)
                    incident.confidence = min(1.0, len(group) / 10)  # Scale with event count
                    incident.generate_title()
                    incidents.append(incident)

        logger.info("time_window_correlated", incidents=len(incidents))
        return incidents

    def _window_group(
        self, sorted_events: list[NormalizedLogEvent]
    ) -> list[list[NormalizedLogEvent]]:
        """Group chronologically sorted events using a sliding time window."""
        if not sorted_events:
            return []

        groups: list[list[NormalizedLogEvent]] = []
        current_group = [sorted_events[0]]

        for event in sorted_events[1:]:
            last_ts = current_group[-1].timestamp
            gap = (event.timestamp - last_ts).total_seconds()

            if gap <= self.window_seconds:
                current_group.append(event)
            else:
                groups.append(current_group)
                current_group = [event]

        groups.append(current_group)
        return groups


class AttackChainCorrelator(BaseCorrelator):
    """Detects multi-stage attack chains based on kill chain progression.

    Looks for sequences like:
        reconnaissance → initial_access → execution → persistence

    A chain is identified when events from the same source IP span
    multiple kill chain stages within a time window.
    """

    name = "attack_chain"

    # Stage ordering for chain detection
    STAGE_ORDER = {
        AttackStage.RECONNAISSANCE: 0,
        AttackStage.INITIAL_ACCESS: 1,
        AttackStage.EXECUTION: 2,
        AttackStage.PERSISTENCE: 3,
        AttackStage.PRIVILEGE_ESCALATION: 4,
        AttackStage.LATERAL_MOVEMENT: 5,
        AttackStage.EXFILTRATION: 6,
        AttackStage.IMPACT: 7,
    }

    def __init__(
        self,
        window_seconds: int = 3600,   # 1 hour — chains span longer windows
        min_stages: int = 2,           # At least 2 different stages
    ) -> None:
        self.window_seconds = window_seconds
        self.min_stages = min_stages

    def correlate(self, events: list[NormalizedLogEvent]) -> list[Incident]:
        """Detect multi-stage attack chains."""
        # Filter to non-benign events with source IPs
        attack_events = [
            e for e in events
            if e.attack_category not in (AttackCategory.BENIGN, AttackCategory.UNKNOWN)
            and e.src_ip
        ]

        if not attack_events:
            return []

        # Group by source IP
        ip_groups: dict[str, list[NormalizedLogEvent]] = defaultdict(list)
        for event in attack_events:
            ip_groups[event.src_ip].append(event)

        incidents = []
        for src_ip, ip_events in ip_groups.items():
            ip_events.sort(key=lambda e: e.timestamp)

            # Check if events span multiple attack stages within the window
            chains = self._find_chains(ip_events)
            for chain_events in chains:
                incident = Incident(correlation_rule=self.name)
                for event in chain_events:
                    incident.add_event(event)

                # Higher confidence for longer chains
                n_stages = len(set(incident.attack_stages) - {"unknown"})
                incident.confidence = min(1.0, n_stages / 4)
                incident.generate_title()
                incidents.append(incident)

        logger.info("attack_chain_correlated", incidents=len(incidents))
        return incidents

    def _find_chains(
        self, sorted_events: list[NormalizedLogEvent]
    ) -> list[list[NormalizedLogEvent]]:
        """Find event sequences that span multiple kill chain stages."""
        if not sorted_events:
            return []

        chains: list[list[NormalizedLogEvent]] = []
        current_chain = [sorted_events[0]]
        current_stages: set[str] = set()

        stage = CATEGORY_TO_STAGE.get(
            sorted_events[0].attack_category, AttackStage.UNKNOWN
        )
        if stage != AttackStage.UNKNOWN:
            current_stages.add(stage.value)

        for event in sorted_events[1:]:
            time_gap = (event.timestamp - current_chain[0].timestamp).total_seconds()

            if time_gap <= self.window_seconds:
                current_chain.append(event)
                stage = CATEGORY_TO_STAGE.get(
                    event.attack_category, AttackStage.UNKNOWN
                )
                if stage != AttackStage.UNKNOWN:
                    current_stages.add(stage.value)
            else:
                # Window expired — check if we have a chain
                if len(current_stages) >= self.min_stages:
                    chains.append(current_chain)
                current_chain = [event]
                current_stages = set()
                stage = CATEGORY_TO_STAGE.get(
                    event.attack_category, AttackStage.UNKNOWN
                )
                if stage != AttackStage.UNKNOWN:
                    current_stages.add(stage.value)

        # Don't forget the last group
        if len(current_stages) >= self.min_stages:
            chains.append(current_chain)

        return chains


class StatisticalCorrelator(BaseCorrelator):
    """DBSCAN-based clustering to find statistically similar events.

    Catches patterns that rule-based correlators miss — novel attacks,
    low-and-slow campaigns, and anomalous traffic that doesn't match
    predefined signatures.

    Uses a subset of features: src_port, dst_port, bytes, packets, duration.
    Events that cluster together get grouped into incidents.
    """

    name = "statistical"

    def __init__(
        self,
        eps: float = 0.5,
        min_samples: int = 5,
        severity_filter: SeverityLevel = SeverityLevel.LOW,
    ) -> None:
        self.eps = eps
        self.min_samples = min_samples
        self.severity_filter = severity_filter
        self._severity_order = {
            SeverityLevel.BENIGN: 0, SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2, SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }

    def correlate(self, events: list[NormalizedLogEvent]) -> list[Incident]:
        """Cluster events using DBSCAN on feature vectors."""
        from sklearn.cluster import DBSCAN
        from sklearn.preprocessing import StandardScaler

        min_level = self._severity_order.get(self.severity_filter, 0)
        filtered = [
            e for e in events
            if self._severity_order.get(e.severity, 0) >= min_level
        ]

        if len(filtered) < self.min_samples:
            return []

        # Extract clustering features
        feature_matrix = self._extract_cluster_features(filtered)

        # Normalize
        scaler = StandardScaler()
        scaled = scaler.fit_transform(feature_matrix)

        # Cluster
        dbscan = DBSCAN(eps=self.eps, min_samples=self.min_samples, metric="euclidean")
        labels = dbscan.fit_predict(scaled)

        # Group events by cluster label (ignore noise = -1)
        clusters: dict[int, list[NormalizedLogEvent]] = defaultdict(list)
        for event, label in zip(filtered, labels):
            if label >= 0:
                clusters[label].append(event)

        incidents = []
        for cluster_id, cluster_events in clusters.items():
            incident = Incident(correlation_rule=f"{self.name}_cluster_{cluster_id}")
            for event in cluster_events:
                incident.add_event(event)

            # Confidence based on cluster tightness
            incident.confidence = min(1.0, len(cluster_events) / 20)
            incident.generate_title()
            incidents.append(incident)

        logger.info("statistical_correlated", incidents=len(incidents), clusters=len(clusters))
        return incidents

    def _extract_cluster_features(
        self, events: list[NormalizedLogEvent]
    ) -> np.ndarray:
        """Extract numeric features for clustering."""
        features = []
        for e in events:
            features.append([
                float(e.dst_port or 0),
                float(e.src_port or 0),
                float(e.bytes_in or 0),
                float(e.bytes_out or 0),
                float(e.flow_duration or 0),
                float(e.total_fwd_packets or 0),
                float(e.total_bwd_packets or 0),
                float(e.flow_bytes_per_sec or 0),
            ])
        return np.array(features)
