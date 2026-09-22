"""Incident data model — a correlated group of related security events.

In SOC terminology, an "incident" is an escalation-worthy finding that
an analyst needs to investigate. It's not a single alert — it's a
collection of related alerts that together tell the story of what happened.

An incident captures:
    - The related events (the evidence)
    - Overall severity (escalated from individual events)
    - Attack chain stage (what phase of an attack this represents)
    - Timeline (first seen → last seen)
    - Affected assets (IPs, hosts)
    - A correlation reason (why these events were grouped)

This maps directly to how Palo Alto Cortex XSIAM structures its incidents.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field

from soc_analyzer.models.schemas import (
    AttackCategory,
    NormalizedLogEvent,
    SeverityLevel,
)


class IncidentSeverity(str, Enum):
    """Incident-level severity — escalated from event severities."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AttackStage(str, Enum):
    """MITRE ATT&CK kill chain stages for attack chain detection."""

    RECONNAISSANCE = "reconnaissance"      # Port scans, service enumeration
    INITIAL_ACCESS = "initial_access"      # Brute force, exploit attempts
    EXECUTION = "execution"                # Code execution, malware
    PERSISTENCE = "persistence"            # Backdoors, account creation
    PRIVILEGE_ESCALATION = "privilege_escalation"  # sudo exploits
    LATERAL_MOVEMENT = "lateral_movement"  # Internal pivoting
    EXFILTRATION = "exfiltration"           # Data theft
    IMPACT = "impact"                      # DDoS, ransomware
    UNKNOWN = "unknown"


# Map attack categories → kill chain stage
CATEGORY_TO_STAGE: dict[AttackCategory, AttackStage] = {
    AttackCategory.PORT_SCAN: AttackStage.RECONNAISSANCE,
    AttackCategory.BRUTE_FORCE: AttackStage.INITIAL_ACCESS,
    AttackCategory.WEB_ATTACK_BRUTEFORCE: AttackStage.INITIAL_ACCESS,
    AttackCategory.WEB_ATTACK_XSS: AttackStage.EXECUTION,
    AttackCategory.WEB_ATTACK_SQL: AttackStage.EXECUTION,
    AttackCategory.HEARTBLEED: AttackStage.EXECUTION,
    AttackCategory.INFILTRATION: AttackStage.LATERAL_MOVEMENT,
    AttackCategory.BOTNET: AttackStage.PERSISTENCE,
    AttackCategory.DOS: AttackStage.IMPACT,
    AttackCategory.DDOS: AttackStage.IMPACT,
    AttackCategory.BENIGN: AttackStage.UNKNOWN,
    AttackCategory.UNKNOWN: AttackStage.UNKNOWN,
}


class Incident(BaseModel):
    """A correlated security incident composed of related events."""

    id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:12].upper()}")
    title: str = ""
    severity: IncidentSeverity = IncidentSeverity.INFO
    status: str = "open"

    # Event references (store IDs to avoid duplication; keep a few for context)
    event_ids: list[str] = Field(default_factory=list)
    event_count: int = 0
    sample_events: list[dict[str, Any]] = Field(default_factory=list, max_length=5)

    # Timeline
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # Attack context
    attack_categories: list[str] = Field(default_factory=list)
    attack_stages: list[str] = Field(default_factory=list)
    correlation_rule: str = ""  # Which strategy created this incident

    # Affected assets
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    target_ports: list[int] = Field(default_factory=list)

    # Severity breakdown
    severity_counts: dict[str, int] = Field(default_factory=dict)

    # Confidence
    confidence: float = 0.0

    @computed_field
    @property
    def duration_seconds(self) -> float:
        """Duration of the incident in seconds."""
        if self.first_seen and self.last_seen:
            return (self.last_seen - self.first_seen).total_seconds()
        return 0.0

    @computed_field
    @property
    def events_per_minute(self) -> float:
        """Rate of events per minute during the incident."""
        if self.duration_seconds > 0:
            return round(self.event_count / (self.duration_seconds / 60), 2)
        return float(self.event_count)

    def add_event(self, event: NormalizedLogEvent) -> None:
        """Add an event to this incident, updating all aggregates."""
        self.event_ids.append(event.id)
        self.event_count = len(self.event_ids)

        # Update timeline
        if self.first_seen is None or event.timestamp < self.first_seen:
            self.first_seen = event.timestamp
        if self.last_seen is None or event.timestamp > self.last_seen:
            self.last_seen = event.timestamp

        # Track attack categories
        if event.attack_category and event.attack_category.value not in self.attack_categories:
            self.attack_categories.append(event.attack_category.value)

        # Track attack stages
        stage = CATEGORY_TO_STAGE.get(event.attack_category, AttackStage.UNKNOWN)
        if stage.value not in self.attack_stages:
            self.attack_stages.append(stage.value)

        # Track affected IPs and ports
        if event.src_ip and event.src_ip not in self.source_ips:
            self.source_ips.append(event.src_ip)
        if event.dst_ip and event.dst_ip not in self.destination_ips:
            self.destination_ips.append(event.dst_ip)
        if event.dst_port and event.dst_port not in self.target_ports:
            self.target_ports.append(event.dst_port)

        # Track severity distribution
        sev = event.severity.value if event.severity else "unknown"
        self.severity_counts[sev] = self.severity_counts.get(sev, 0) + 1

        # Keep a few sample events for context
        if len(self.sample_events) < 5:
            self.sample_events.append({
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "event_name": event.event_name,
                "severity": event.severity.value,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "dst_port": event.dst_port,
                "attack_category": event.attack_category.value if event.attack_category else None,
            })

        # Recalculate incident severity (highest event severity escalates)
        self._recalculate_severity()

    def _recalculate_severity(self) -> None:
        """Escalate incident severity based on event composition.

        Rules:
            - Any critical event → incident is critical
            - 3+ high events → incident is critical
            - Any high event → incident is high
            - 5+ medium events → incident is high
            - Multi-stage attack chain → escalate by one level
        """
        counts = self.severity_counts
        n_critical = counts.get("critical", 0)
        n_high = counts.get("high", 0)
        n_medium = counts.get("medium", 0)

        if n_critical > 0 or n_high >= 3:
            self.severity = IncidentSeverity.CRITICAL
        elif n_high > 0:
            self.severity = IncidentSeverity.HIGH
        elif n_medium >= 5:
            self.severity = IncidentSeverity.HIGH
        elif n_medium > 0:
            self.severity = IncidentSeverity.MEDIUM
        else:
            self.severity = IncidentSeverity.LOW

        # Multi-stage attack chain escalation
        non_unknown_stages = [s for s in self.attack_stages if s != "unknown"]
        if len(non_unknown_stages) >= 2:
            escalation = {
                IncidentSeverity.LOW: IncidentSeverity.MEDIUM,
                IncidentSeverity.MEDIUM: IncidentSeverity.HIGH,
                IncidentSeverity.HIGH: IncidentSeverity.CRITICAL,
            }
            self.severity = escalation.get(self.severity, self.severity)

    def generate_title(self) -> str:
        """Auto-generate a descriptive incident title."""
        primary_category = self.attack_categories[0] if self.attack_categories else "unknown"
        primary_src = self.source_ips[0] if self.source_ips else "unknown"
        n_targets = len(self.destination_ips)

        category_labels = {
            "brute_force": "Brute Force Attack",
            "port_scan": "Port Scan",
            "ddos": "DDoS Attack",
            "dos": "DoS Attack",
            "botnet": "Botnet Activity",
            "infiltration": "Network Infiltration",
            "web_attack_xss": "XSS Attack",
            "web_attack_sql": "SQL Injection",
            "web_attack_bruteforce": "Web Brute Force",
            "heartbleed": "Heartbleed Exploit",
        }
        label = category_labels.get(primary_category, primary_category.replace("_", " ").title())

        target_str = f"targeting {n_targets} host{'s' if n_targets > 1 else ''}" if n_targets > 0 else ""
        chain_str = ""
        if len(self.attack_stages) >= 2:
            chain_str = f" (multi-stage: {' → '.join(self.attack_stages[:3])})"

        self.title = f"{label} from {primary_src} {target_str}{chain_str}".strip()
        return self.title
