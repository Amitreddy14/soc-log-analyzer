"""Parser for authentication logs (auth.log / secure).

Auth logs are the #1 signal source for brute force attacks, credential stuffing,
privilege escalation, and unauthorized access. Every SOC analyst's bread and butter.

Covers:
    - SSH login attempts (accepted, failed, invalid user)
    - sudo usage (success, failure)
    - PAM authentication events
    - Account lockouts and session events
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

# Auth log patterns
AUTH_PATTERNS = {
    "ssh_accepted": re.compile(
        r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)\s+port\s+(?P<src_port>\d+)"
    ),
    "ssh_failed": re.compile(
        r"Failed\s+(?P<method>\S+)\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)\s+port\s+(?P<src_port>\d+)"
    ),
    "ssh_invalid_user": re.compile(
        r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<src_ip>[\d.]+)(?:\s+port\s+(?P<src_port>\d+))?"
    ),
    "sudo_success": re.compile(
        r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)"
    ),
    "sudo_failed": re.compile(
        r"(?P<user>\S+)\s*:\s*.*(?:NOT\s+in\s+sudoers|incorrect\s+password\s+attempts)"
    ),
    "session_opened": re.compile(
        r"session\s+opened\s+for\s+user\s+(?P<user>\S+)"
    ),
    "session_closed": re.compile(
        r"session\s+closed\s+for\s+user\s+(?P<user>\S+)"
    ),
}

# Syslog-style log line
AUTH_LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+(?P<hostname>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)


class AuthLogParser(BaseParser):
    """Parser for Linux auth.log / secure files."""

    source_type = LogSource.AUTH

    def parse_file(self, filepath: Path) -> Iterator[RawLogEvent]:
        """Parse an auth log file line by line."""
        logger.info("parsing_auth_log", file=str(filepath))

        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                match = AUTH_LINE_PATTERN.match(line)
                if not match:
                    continue

                groups = match.groupdict()

                try:
                    timestamp = datetime.strptime(
                        f"{datetime.now().year} {groups['timestamp']}",
                        "%Y %b %d %H:%M:%S",
                    )
                except ValueError:
                    timestamp = datetime.now()

                # Enrich with auth-specific pattern matching
                message = groups.get("message", "")
                auth_data = {"_auth_event_type": "unknown"}

                for event_type, pattern in AUTH_PATTERNS.items():
                    auth_match = pattern.search(message)
                    if auth_match:
                        auth_data = auth_match.groupdict()
                        auth_data["_auth_event_type"] = event_type
                        break

                combined_data = {**groups, **auth_data}

                yield RawLogEvent(
                    timestamp=timestamp,
                    source=LogSource.AUTH,
                    raw_data=combined_data,
                    raw_text=line,
                )

    def normalize(self, raw_event: RawLogEvent) -> NormalizedLogEvent:
        """Normalize an auth log event into the unified CEF schema."""
        data = raw_event.raw_data
        event_type = data.get("_auth_event_type", "unknown")

        severity, attack_cat, event_name, action, outcome = self._classify_auth_event(
            event_type, data
        )

        return NormalizedLogEvent(
            raw_event_id=raw_event.id,
            timestamp=raw_event.timestamp,
            device_vendor="Linux",
            device_product=data.get("service", "auth"),
            signature_id=f"AUTH-{event_type}",
            event_name=event_name,
            severity=severity,
            src_ip=data.get("src_ip"),
            src_port=int(data["src_port"]) if data.get("src_port") else None,
            protocol="TCP",
            action=action,
            outcome=outcome,
            source_type=LogSource.AUTH,
            source_host=data.get("hostname"),
            attack_category=attack_cat,
            extra={
                "user": data.get("user"),
                "target_user": data.get("target_user"),
                "method": data.get("method"),
                "command": data.get("command"),
                "service": data.get("service"),
            },
        )

    def _classify_auth_event(
        self, event_type: str, data: dict
    ) -> tuple[SeverityLevel, AttackCategory, str, str, str]:
        """Classify an auth event by type.

        Returns:
            (severity, attack_category, event_name, action, outcome)
        """
        user = data.get("user", "unknown")

        match event_type:
            case "ssh_accepted":
                return (SeverityLevel.BENIGN, AttackCategory.BENIGN,
                        f"SSH login accepted for {user}", "allow", "success")

            case "ssh_failed":
                return (SeverityLevel.MEDIUM, AttackCategory.BRUTE_FORCE,
                        f"SSH login failed for {user}", "deny", "failure")

            case "ssh_invalid_user":
                return (SeverityLevel.HIGH, AttackCategory.BRUTE_FORCE,
                        f"SSH attempt with invalid user {user}", "deny", "failure")

            case "sudo_success":
                cmd = data.get("command", "")[:80]
                return (SeverityLevel.LOW, AttackCategory.BENIGN,
                        f"sudo by {user}: {cmd}", "allow", "success")

            case "sudo_failed":
                return (SeverityLevel.HIGH, AttackCategory.INFILTRATION,
                        f"sudo failure for {user}", "deny", "failure")

            case "session_opened":
                return (SeverityLevel.BENIGN, AttackCategory.BENIGN,
                        f"Session opened for {user}", "allow", "success")

            case "session_closed":
                return (SeverityLevel.BENIGN, AttackCategory.BENIGN,
                        f"Session closed for {user}", "allow", "success")

            case _:
                return (SeverityLevel.LOW, AttackCategory.UNKNOWN,
                        data.get("message", "Unknown auth event")[:120], "unknown", "unknown")
