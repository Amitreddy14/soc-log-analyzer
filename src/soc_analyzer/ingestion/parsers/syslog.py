"""Parser for standard syslog (RFC 5424 / RFC 3164) messages.

Syslog is the backbone of Unix/Linux logging. Every server, router, and network
device ships logs via syslog. SOC analysts see these as a firehose of system
events that occasionally contain indicators of compromise.

RFC 3164 (BSD) format:
    <priority>timestamp hostname app[pid]: message

RFC 5424 (IETF) format:
    <priority>version timestamp hostname app-name procid msgid structured-data msg
"""

from __future__ import annotations

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

# RFC 3164 pattern
RFC3164_PATTERN = re.compile(
    r"^(?:<(?P<priority>\d+)>)?"
    r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>\S+?)(?:\[(?P<pid>\d+)\])?"
    r":\s+(?P<message>.+)$"
)

# Syslog severity levels (RFC 5424)
SYSLOG_SEVERITY = {
    0: SeverityLevel.CRITICAL,   # Emergency
    1: SeverityLevel.CRITICAL,   # Alert
    2: SeverityLevel.CRITICAL,   # Critical
    3: SeverityLevel.HIGH,       # Error
    4: SeverityLevel.MEDIUM,     # Warning
    5: SeverityLevel.LOW,        # Notice
    6: SeverityLevel.BENIGN,     # Informational
    7: SeverityLevel.BENIGN,     # Debug
}

# Patterns that indicate security-relevant events
SECURITY_PATTERNS = [
    (re.compile(r"failed\s+password|authentication\s+fail", re.I), AttackCategory.BRUTE_FORCE, SeverityLevel.MEDIUM),
    (re.compile(r"invalid\s+user|unknown\s+user", re.I), AttackCategory.BRUTE_FORCE, SeverityLevel.MEDIUM),
    (re.compile(r"connection\s+refused|connection\s+reset", re.I), AttackCategory.PORT_SCAN, SeverityLevel.LOW),
    (re.compile(r"segfault|buffer\s+overflow|stack\s+smash", re.I), AttackCategory.INFILTRATION, SeverityLevel.CRITICAL),
    (re.compile(r"malware|trojan|virus|ransomware", re.I), AttackCategory.BOTNET, SeverityLevel.CRITICAL),
    (re.compile(r"denied|blocked|violation", re.I), AttackCategory.UNKNOWN, SeverityLevel.LOW),
]


class SyslogParser(BaseParser):
    """Parser for syslog-formatted log files."""

    source_type = LogSource.SYSLOG

    def parse_file(self, filepath: Path) -> Iterator[RawLogEvent]:
        """Parse a syslog file line by line."""
        logger.info("parsing_syslog", file=str(filepath))

        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                match = RFC3164_PATTERN.match(line)
                if not match:
                    logger.debug("syslog_no_match", line_num=line_num)
                    continue

                groups = match.groupdict()

                try:
                    timestamp = datetime.strptime(
                        f"{datetime.now().year} {groups['timestamp']}",
                        "%Y %b %d %H:%M:%S",
                    )
                except ValueError:
                    timestamp = datetime.now()

                yield RawLogEvent(
                    timestamp=timestamp,
                    source=LogSource.SYSLOG,
                    raw_data=groups,
                    raw_text=line,
                )

    def _extract_priority_severity(self, priority_str: str | None) -> SeverityLevel:
        """Extract severity from syslog priority value.

        Priority = (Facility * 8) + Severity
        """
        if not priority_str:
            return SeverityLevel.LOW
        try:
            priority = int(priority_str)
            severity_num = priority % 8
            return SYSLOG_SEVERITY.get(severity_num, SeverityLevel.LOW)
        except ValueError:
            return SeverityLevel.LOW

    def _analyze_message(self, message: str) -> tuple[AttackCategory, SeverityLevel | None]:
        """Analyze syslog message content for security indicators."""
        for pattern, category, severity in SECURITY_PATTERNS:
            if pattern.search(message):
                return category, severity
        return AttackCategory.BENIGN, None

    def normalize(self, raw_event: RawLogEvent) -> NormalizedLogEvent:
        """Normalize a syslog event into the unified CEF schema."""
        data = raw_event.raw_data
        message = data.get("message", "")

        # Determine severity from priority field and message content
        priority_severity = self._extract_priority_severity(data.get("priority"))
        attack_cat, message_severity = self._analyze_message(message)

        # Message-based severity overrides priority if it's higher
        severity = message_severity if message_severity and message_severity != SeverityLevel.BENIGN else priority_severity

        return NormalizedLogEvent(
            raw_event_id=raw_event.id,
            timestamp=raw_event.timestamp,
            device_vendor="Syslog",
            device_product=data.get("app", "unknown"),
            signature_id=f"SYSLOG-{data.get('app', 'unknown')}",
            event_name=message[:120],  # Truncate for readability
            severity=severity,
            source_type=LogSource.SYSLOG,
            source_host=data.get("hostname"),
            attack_category=attack_cat,
            extra={
                "pid": data.get("pid"),
                "full_message": message,
            },
        )
