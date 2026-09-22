"""Correlation engine — orchestrates strategies and merges overlapping incidents.

The engine runs all correlation strategies, then merges incidents that share
events (i.e., when two strategies detect the same underlying attack from
different angles, we want one unified incident, not two duplicates).

This mirrors how Palo Alto Cortex XSIAM's correlation engine works:
    1. Multiple detection rules fire independently
    2. Incidents are created per rule
    3. Overlapping incidents get merged into a single investigation
    4. The merged incident inherits the highest severity

Usage:
    engine = CorrelationEngine()
    incidents = engine.correlate(events)
    for incident in engine.get_critical_incidents():
        print(incident.title, incident.severity)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from soc_analyzer.correlation.incidents import Incident, IncidentSeverity
from soc_analyzer.correlation.strategies import (
    AttackChainCorrelator,
    BaseCorrelator,
    StatisticalCorrelator,
    TimeWindowCorrelator,
)
from soc_analyzer.models.schemas import NormalizedLogEvent
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


class CorrelationEngine:
    """Orchestrates correlation strategies and manages incidents.

    Args:
        strategies: List of correlator instances. If None, uses defaults.
        merge_overlap_threshold: Fraction of shared events required to merge
            two incidents (0.3 = 30% overlap triggers merge).
    """

    def __init__(
        self,
        strategies: list[BaseCorrelator] | None = None,
        merge_overlap_threshold: float = 0.3,
    ) -> None:
        self.strategies = strategies or [
            TimeWindowCorrelator(window_seconds=300, min_events=3),
            AttackChainCorrelator(window_seconds=3600, min_stages=2),
            StatisticalCorrelator(eps=0.5, min_samples=5),
        ]
        self.merge_overlap_threshold = merge_overlap_threshold
        self.incidents: list[Incident] = []
        self._correlation_stats: dict[str, Any] = {}

    def correlate(self, events: list[NormalizedLogEvent]) -> list[Incident]:
        """Run all correlation strategies and merge results.

        Args:
            events: List of normalized events to correlate.

        Returns:
            List of deduplicated, merged incidents sorted by severity.
        """
        logger.info("correlation_started", n_events=len(events))
        all_incidents: list[Incident] = []
        strategy_stats: dict[str, int] = {}

        for strategy in self.strategies:
            try:
                strategy_incidents = strategy.correlate(events)
                all_incidents.extend(strategy_incidents)
                strategy_stats[strategy.name] = len(strategy_incidents)
                logger.info(
                    "strategy_complete",
                    strategy=strategy.name,
                    incidents=len(strategy_incidents),
                )
            except Exception as e:
                logger.error(
                    "strategy_failed",
                    strategy=strategy.name,
                    error=str(e),
                )
                strategy_stats[strategy.name] = 0

        # Merge overlapping incidents
        merged = self._merge_overlapping(all_incidents)

        # Sort by severity (critical first) then by event count
        severity_order = {
            IncidentSeverity.CRITICAL: 0,
            IncidentSeverity.HIGH: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.LOW: 3,
            IncidentSeverity.INFO: 4,
        }
        merged.sort(key=lambda i: (severity_order.get(i.severity, 5), -i.event_count))

        # Assign incident IDs to source events
        for incident in merged:
            for event in events:
                if event.id in incident.event_ids:
                    event.incident_id = incident.id

        self.incidents = merged
        self._correlation_stats = {
            "total_events": len(events),
            "total_incidents_pre_merge": len(all_incidents),
            "total_incidents_post_merge": len(merged),
            "by_strategy": strategy_stats,
            "by_severity": self._count_by_severity(merged),
            "events_correlated": sum(i.event_count for i in merged),
            "events_uncorrelated": len(events) - len(
                {eid for i in merged for eid in i.event_ids}
            ),
        }

        logger.info(
            "correlation_complete",
            pre_merge=len(all_incidents),
            post_merge=len(merged),
        )
        return merged

    def _merge_overlapping(self, incidents: list[Incident]) -> list[Incident]:
        """Merge incidents that share significant event overlap.

        Uses union-find to group incidents with overlapping events,
        then merges each group into a single incident.
        """
        if len(incidents) <= 1:
            return incidents

        n = len(incidents)
        parent = list(range(n))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: int, y: int) -> None:
            px, py = find(x), find(y)
            if px != py:
                parent[px] = py

        # Build event → incident index
        event_to_incidents: dict[str, list[int]] = defaultdict(list)
        for idx, incident in enumerate(incidents):
            for eid in incident.event_ids:
                event_to_incidents[eid].append(idx)

        # Check overlap between incidents sharing events
        for event_id, inc_indices in event_to_incidents.items():
            for i in range(len(inc_indices)):
                for j in range(i + 1, len(inc_indices)):
                    idx_a, idx_b = inc_indices[i], inc_indices[j]
                    set_a = set(incidents[idx_a].event_ids)
                    set_b = set(incidents[idx_b].event_ids)
                    overlap = len(set_a & set_b)
                    min_size = min(len(set_a), len(set_b))
                    if min_size > 0 and overlap / min_size >= self.merge_overlap_threshold:
                        union(idx_a, idx_b)

        # Group by root
        groups: dict[int, list[int]] = defaultdict(list)
        for idx in range(n):
            groups[find(idx)].append(idx)

        # Merge each group
        merged: list[Incident] = []
        for group_indices in groups.values():
            if len(group_indices) == 1:
                merged.append(incidents[group_indices[0]])
            else:
                merged_incident = self._merge_incident_group(
                    [incidents[i] for i in group_indices]
                )
                merged.append(merged_incident)

        return merged

    def _merge_incident_group(self, incidents: list[Incident]) -> Incident:
        """Merge multiple incidents into a single incident."""
        merged = Incident(
            correlation_rule="merged:" + "+".join(i.correlation_rule for i in incidents),
        )

        # Collect all unique event IDs
        seen_ids: set[str] = set()
        for incident in incidents:
            for eid in incident.event_ids:
                if eid not in seen_ids:
                    merged.event_ids.append(eid)
                    seen_ids.add(eid)

        merged.event_count = len(merged.event_ids)

        # Merge timelines
        first_times = [i.first_seen for i in incidents if i.first_seen]
        last_times = [i.last_seen for i in incidents if i.last_seen]
        if first_times:
            merged.first_seen = min(first_times)
        if last_times:
            merged.last_seen = max(last_times)

        # Merge attack context
        for incident in incidents:
            for cat in incident.attack_categories:
                if cat not in merged.attack_categories:
                    merged.attack_categories.append(cat)
            for stage in incident.attack_stages:
                if stage not in merged.attack_stages:
                    merged.attack_stages.append(stage)
            for ip in incident.source_ips:
                if ip not in merged.source_ips:
                    merged.source_ips.append(ip)
            for ip in incident.destination_ips:
                if ip not in merged.destination_ips:
                    merged.destination_ips.append(ip)
            for port in incident.target_ports:
                if port not in merged.target_ports:
                    merged.target_ports.append(port)

        # Merge severity counts
        for incident in incidents:
            for sev, count in incident.severity_counts.items():
                merged.severity_counts[sev] = merged.severity_counts.get(sev, 0) + count

        # Merge sample events (take first 5 unique)
        seen_sample_ids: set[str] = set()
        for incident in incidents:
            for sample in incident.sample_events:
                if sample["id"] not in seen_sample_ids and len(merged.sample_events) < 5:
                    merged.sample_events.append(sample)
                    seen_sample_ids.add(sample["id"])

        # Highest confidence
        merged.confidence = max(i.confidence for i in incidents)

        # Recalculate severity
        merged._recalculate_severity()
        merged.generate_title()

        return merged

    def get_critical_incidents(self) -> list[Incident]:
        """Return only critical and high severity incidents."""
        return [
            i for i in self.incidents
            if i.severity in (IncidentSeverity.CRITICAL, IncidentSeverity.HIGH)
        ]

    def get_stats(self) -> dict[str, Any]:
        """Return correlation statistics."""
        return self._correlation_stats

    @staticmethod
    def _count_by_severity(incidents: list[Incident]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for i in incidents:
            counts[i.severity.value] = counts.get(i.severity.value, 0) + 1
        return counts

    def print_summary(self) -> None:
        """Print a summary of correlation results."""
        stats = self._correlation_stats
        if not stats:
            console.print("[yellow]No correlation results. Run correlate() first.[/]")
            return

        console.print(Panel(
            f"[bold]{stats['total_events']:,}[/] events → "
            f"[bold green]{stats['total_incidents_post_merge']}[/] incidents "
            f"({stats['events_correlated']} events correlated, "
            f"{stats['events_uncorrelated']} uncorrelated)",
            title="Correlation Summary",
        ))

        # Strategy breakdown
        if stats.get("by_strategy"):
            table = Table(title="By Strategy")
            table.add_column("Strategy", style="bold")
            table.add_column("Incidents", justify="right")
            for strat, count in stats["by_strategy"].items():
                table.add_row(strat.replace("_", " ").title(), str(count))
            console.print(table)

        # Incidents table
        if self.incidents:
            table = Table(title="Incidents")
            table.add_column("ID", style="dim")
            table.add_column("Severity", style="bold")
            table.add_column("Title")
            table.add_column("Events", justify="right")
            table.add_column("Sources")
            table.add_column("Duration")
            table.add_column("Confidence", justify="right")

            for inc in self.incidents[:20]:  # Top 20
                sev_style = {
                    "critical": "red", "high": "yellow",
                    "medium": "cyan", "low": "blue",
                }.get(inc.severity.value, "")

                duration = ""
                if inc.duration_seconds > 0:
                    mins = int(inc.duration_seconds // 60)
                    secs = int(inc.duration_seconds % 60)
                    duration = f"{mins}m {secs}s" if mins else f"{secs}s"

                table.add_row(
                    inc.id[:16],
                    f"[{sev_style}]{inc.severity.value.upper()}[/]",
                    inc.title[:60],
                    str(inc.event_count),
                    ", ".join(inc.source_ips[:3]),
                    duration,
                    f"{inc.confidence:.2f}",
                )

            console.print(table)
