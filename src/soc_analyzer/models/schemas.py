"""Unified log schemas based on Common Event Format (CEF).

CEF is the industry standard used by Palo Alto (Cortex XSIAM), Splunk, ArcSight,
and most major SIEMs. Our normalized schema maps directly to CEF fields, making
this pipeline compatible with real-world SOC tooling.

CEF Format Reference:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions

We extend CEF with ML-specific fields (predicted_severity, confidence, cluster_id)
that the classification and correlation phases will populate.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    """CEF-aligned severity levels (0-10 scale mapped to categories)."""

    CRITICAL = "critical"   # CEF 9-10: Immediate threat, active exploitation
    HIGH = "high"           # CEF 7-8:  Likely attack, needs urgent review
    MEDIUM = "medium"       # CEF 4-6:  Suspicious activity, investigate
    LOW = "low"             # CEF 1-3:  Informational anomaly
    BENIGN = "benign"       # CEF 0:    Normal operations


class LogSource(str, Enum):
    """Supported log source types."""

    FIREWALL = "firewall"
    IDS = "ids"
    SYSLOG = "syslog"
    AUTH = "auth"
    ENDPOINT = "endpoint"
    NETFLOW = "netflow"
    CICIDS = "cicids"       # CICIDS-2017 dataset


class AttackCategory(str, Enum):
    """MITRE ATT&CK-aligned attack categories."""

    BENIGN = "benign"
    DOS = "dos"
    DDOS = "ddos"
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    BOTNET = "botnet"
    INFILTRATION = "infiltration"
    WEB_ATTACK_XSS = "web_attack_xss"
    WEB_ATTACK_SQL = "web_attack_sql"
    WEB_ATTACK_BRUTEFORCE = "web_attack_bruteforce"
    HEARTBLEED = "heartbleed"
    UNKNOWN = "unknown"


class RawLogEvent(BaseModel):
    """A raw log event as ingested — before normalization.

    This preserves the original data for audit trail and re-processing.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    source: LogSource
    raw_data: dict[str, Any]
    raw_text: str | None = None  # Original log line if text-based

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class NormalizedLogEvent(BaseModel):
    """CEF-normalized log event — the unified schema all sources map to.

    This is the core data structure that flows through the entire pipeline:
    ingestion → classification → correlation → summarization.
    """

    # --- Identity ---
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    raw_event_id: str | None = None  # Link back to RawLogEvent

    # --- CEF Header Fields ---
    timestamp: datetime
    device_vendor: str = "SOCAnalyzer"
    device_product: str = "Pipeline"
    signature_id: str = ""            # Rule/signature that triggered
    event_name: str = ""              # Human-readable event name
    severity: SeverityLevel = SeverityLevel.BENIGN

    # --- CEF Extension Fields (Network) ---
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None       # TCP, UDP, ICMP, etc.
    bytes_in: int | None = None
    bytes_out: int | None = None

    # --- CEF Extension Fields (Action) ---
    action: str | None = None         # allow, deny, drop, alert
    outcome: str | None = None        # success, failure

    # --- Source Metadata ---
    source_type: LogSource
    source_host: str | None = None    # Hostname of the reporting device

    # --- Attack Classification (populated by Phase 2) ---
    attack_category: AttackCategory = AttackCategory.UNKNOWN
    predicted_severity: SeverityLevel | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    # --- Correlation (populated by Phase 3) ---
    incident_id: str | None = None

    # --- Flow Features (for ML — from CICIDS or computed) ---
    flow_duration: float | None = None
    total_fwd_packets: int | None = None
    total_bwd_packets: int | None = None
    flow_bytes_per_sec: float | None = None
    flow_packets_per_sec: float | None = None
    fwd_packet_length_mean: float | None = None
    bwd_packet_length_mean: float | None = None

    # --- Extensible metadata ---
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, str):
            # Handle common log timestamp formats
            for fmt in [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%d/%m/%Y %H:%M:%S",
                "%d/%m/%Y %H:%M",
            ]:
                try:
                    return datetime.strptime(v, fmt)
                except ValueError:
                    continue
            from dateutil import parser
            return parser.parse(v)
        return v

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}
