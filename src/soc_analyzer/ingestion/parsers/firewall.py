"""Parser for firewall logs (PAN-OS / iptables style).

Real firewall logs from Palo Alto PAN-OS, Cisco ASA, or iptables follow
predictable patterns. This parser handles both real PAN-OS CSV traffic logs
and our synthetic equivalents generated for demo/testing.

PAN-OS Traffic Log Fields (subset):
    Receive Time, Serial, Type, Subtype, Source, Destination, NAT Source,
    NAT Destination, Rule, Application, Source Zone, Destination Zone,
    Action, Bytes Sent, Bytes Received, Repeat Count, ...
"""

from __future__ import annotations

import csv
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from soc_analyzer.ingestion.parsers.base import BaseParser
from soc_analyzer.models.schemas import (
    AttackCategory,
    LogSource,
    NormalizedLogEvent,
    RawLogEvent,
    SeverityLevel,
)
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)

# Regex for common iptables-style log lines
IPTABLES_PATTERN = re.compile(
    r"(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+kernel:.*?"
    r"(?P<action>ACCEPT|DROP|REJECT).*?"
    r"SRC=(?P<src_ip>[\d.]+).*?"
    r"DST=(?P<dst_ip>[\d.]+).*?"
    r"SPT=(?P<src_port>\d+).*?"
    r"DPT=(?P<dst_port>\d+).*?"
    r"PROTO=(?P<protocol>\w+)",
    re.DOTALL,
)

# Suspicious port-based heuristics
HIGH_RISK_PORTS = {22, 23, 3389, 445, 1433, 3306, 5432}
SCAN_THRESHOLD_PORTS = {0, 1, 7, 9, 13, 17, 19, 79, 111, 135, 139, 161}


class FirewallLogParser(BaseParser):
    """Parser for firewall log formats (iptables text, PAN-OS CSV)."""

    source_type = LogSource.FIREWALL

    def parse_file(self, filepath: Path) -> Iterator[RawLogEvent]:
        """Parse firewall logs — auto-detects CSV vs text format."""
        suffix = filepath.suffix.lower()

        if suffix == ".csv":
            yield from self._parse_csv(filepath)
        else:
            yield from self._parse_text(filepath)

    def _parse_csv(self, filepath: Path) -> Iterator[RawLogEvent]:
        """Parse PAN-OS style CSV traffic logs."""
        logger.info("parsing_firewall_csv", file=str(filepath))

        with open(filepath, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                timestamp_str = row.get("Receive Time", row.get("timestamp", ""))
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
                except (ValueError, TypeError):
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    except (ValueError, TypeError):
                        timestamp = datetime.now()

                yield RawLogEvent(
                    timestamp=timestamp,
                    source=LogSource.FIREWALL,
                    raw_data=dict(row),
                )

    def _parse_text(self, filepath: Path) -> Iterator[RawLogEvent]:
        """Parse iptables-style text logs."""
        logger.info("parsing_firewall_text", file=str(filepath))

        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                match = IPTABLES_PATTERN.search(line)
                if not match:
                    continue

                groups = match.groupdict()
                try:
                    # Syslog timestamp (assumes current year)
                    timestamp = datetime.strptime(
                        f"{datetime.now().year} {groups['timestamp']}",
                        "%Y %b %d %H:%M:%S",
                    )
                except ValueError:
                    timestamp = datetime.now()

                yield RawLogEvent(
                    timestamp=timestamp,
                    source=LogSource.FIREWALL,
                    raw_data=groups,
                    raw_text=line,
                )

    def _assess_severity(self, data: dict) -> tuple[SeverityLevel, AttackCategory]:
        """Heuristic severity assessment for firewall events."""
        action = str(data.get("action", data.get("Action", ""))).upper()
        dst_port = int(data.get("dst_port", data.get("Destination Port", 0)) or 0)

        # Denied traffic to high-risk ports
        if action in ("DROP", "REJECT", "deny") and dst_port in HIGH_RISK_PORTS:
            return SeverityLevel.HIGH, AttackCategory.BRUTE_FORCE

        # Traffic to scan-indicator ports
        if dst_port in SCAN_THRESHOLD_PORTS:
            return SeverityLevel.MEDIUM, AttackCategory.PORT_SCAN

        # Any denied traffic is worth noting
        if action in ("DROP", "REJECT", "deny"):
            return SeverityLevel.LOW, AttackCategory.UNKNOWN

        return SeverityLevel.BENIGN, AttackCategory.BENIGN

    def normalize(self, raw_event: RawLogEvent) -> NormalizedLogEvent:
        """Normalize a firewall log event into unified CEF schema."""
        data = raw_event.raw_data
        severity, attack_cat = self._assess_severity(data)

        return NormalizedLogEvent(
            raw_event_id=raw_event.id,
            timestamp=raw_event.timestamp,
            device_vendor="Firewall",
            device_product=data.get("hostname", "iptables"),
            signature_id=f"FW-{data.get('action', 'UNKNOWN')}",
            event_name=f"Firewall {data.get('action', 'event')}",
            severity=severity,
            src_ip=data.get("src_ip", data.get("Source", "")),
            src_port=int(data.get("src_port", data.get("Source Port", 0)) or 0),
            dst_ip=data.get("dst_ip", data.get("Destination", "")),
            dst_port=int(data.get("dst_port", data.get("Destination Port", 0)) or 0),
            protocol=data.get("protocol", data.get("Protocol", "")),
            action=data.get("action", data.get("Action", "")),
            source_type=LogSource.FIREWALL,
            source_host=data.get("hostname"),
            attack_category=attack_cat,
        )
