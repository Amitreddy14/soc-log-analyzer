"""Template-based incident summarizer — works offline, no API key needed.

Generates structured incident reports using rule-based templates.
While not as nuanced as LLM-generated reports, these templates capture
the essential information a SOC analyst needs to act.

This serves as:
    1. A fallback when no LLM API key is configured
    2. A baseline to compare LLM-generated reports against
    3. A fast option for bulk report generation
"""

from __future__ import annotations

from soc_analyzer.correlation.incidents import Incident, IncidentSeverity
from soc_analyzer.summarization.report import IncidentReport, IoC, ResponseAction
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)

# MITRE ATT&CK technique mapping
CATEGORY_TO_MITRE: dict[str, list[str]] = {
    "port_scan": ["T1046 - Network Service Discovery"],
    "brute_force": ["T1110 - Brute Force", "T1110.001 - Password Guessing"],
    "web_attack_bruteforce": ["T1110 - Brute Force", "T1190 - Exploit Public-Facing Application"],
    "web_attack_xss": ["T1059.007 - JavaScript", "T1189 - Drive-by Compromise"],
    "web_attack_sql": ["T1190 - Exploit Public-Facing Application", "T1505.003 - Web Shell"],
    "ddos": ["T1498 - Network Denial of Service", "T1498.001 - Direct Network Flood"],
    "dos": ["T1499 - Endpoint Denial of Service"],
    "botnet": ["T1583.005 - Botnet", "T1071 - Application Layer Protocol"],
    "infiltration": ["T1078 - Valid Accounts", "T1021 - Remote Services"],
    "heartbleed": ["T1190 - Exploit Public-Facing Application"],
}

# Attack category descriptions
CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "port_scan": "systematic network reconnaissance to identify open services and potential entry points",
    "brute_force": "repeated authentication attempts using common or dictionary-based credentials to gain unauthorized access",
    "web_attack_bruteforce": "automated credential stuffing against web application login endpoints",
    "web_attack_xss": "cross-site scripting attack attempting to inject malicious scripts into web responses",
    "web_attack_sql": "SQL injection attack attempting to manipulate database queries through unsanitized input",
    "ddos": "distributed denial of service attack using multiple sources to overwhelm target infrastructure",
    "dos": "denial of service attack targeting service availability",
    "botnet": "command-and-control traffic indicative of compromised hosts communicating with a botnet infrastructure",
    "infiltration": "unauthorized network penetration with evidence of lateral movement between internal systems",
    "heartbleed": "exploitation of the Heartbleed vulnerability (CVE-2014-0160) in OpenSSL to extract sensitive memory data",
}

# Response action templates by severity
RESPONSE_TEMPLATES: dict[IncidentSeverity, list[dict]] = {
    IncidentSeverity.CRITICAL: [
        {"priority": 1, "action": "Immediately isolate affected hosts from the network",
         "rationale": "Prevent lateral movement and data exfiltration while investigation proceeds"},
        {"priority": 1, "action": "Block source IPs at the perimeter firewall",
         "rationale": "Cut off attacker's active communication channel"},
        {"priority": 1, "action": "Escalate to Incident Response team and CISO",
         "rationale": "Critical severity incidents require leadership awareness and IR team engagement"},
        {"priority": 2, "action": "Capture forensic images of affected systems before remediation",
         "rationale": "Preserve evidence for root cause analysis and potential legal proceedings"},
        {"priority": 2, "action": "Rotate credentials for all accounts that accessed affected systems",
         "rationale": "Compromised credentials may have been harvested during the incident"},
    ],
    IncidentSeverity.HIGH: [
        {"priority": 1, "action": "Block source IPs at the perimeter firewall",
         "rationale": "Prevent ongoing attack activity from reaching internal systems"},
        {"priority": 2, "action": "Review authentication logs for targeted accounts for signs of compromise",
         "rationale": "Determine if any brute force attempts were successful"},
        {"priority": 2, "action": "Implement rate limiting on targeted services",
         "rationale": "Reduce the attack surface while maintaining service availability"},
        {"priority": 3, "action": "Update IDS/IPS signatures for the observed attack patterns",
         "rationale": "Improve detection of similar attacks in the future"},
    ],
    IncidentSeverity.MEDIUM: [
        {"priority": 2, "action": "Add source IPs to the watchlist for enhanced monitoring",
         "rationale": "Track potential escalation of reconnaissance activity"},
        {"priority": 3, "action": "Review firewall rules for targeted ports and services",
         "rationale": "Ensure only necessary services are exposed to external networks"},
        {"priority": 3, "action": "Verify targeted systems are fully patched",
         "rationale": "Reconnaissance often precedes exploitation of known vulnerabilities"},
    ],
    IncidentSeverity.LOW: [
        {"priority": 3, "action": "Log the incident for trend analysis",
         "rationale": "Low-severity events may indicate early stages of a larger campaign"},
        {"priority": 3, "action": "Review source IPs against threat intelligence feeds",
         "rationale": "Determine if the source is a known threat actor"},
    ],
}


class TemplateSummarizer:
    """Generate incident reports using rule-based templates."""

    def summarize(self, incident: Incident) -> IncidentReport:
        """Generate a complete incident report from an Incident."""
        logger.info("template_summarizing", incident_id=incident.id)

        report = IncidentReport(
            incident_id=incident.id,
            generator="template",
            severity=incident.severity.value,
            title=incident.title or incident.generate_title(),
            event_count=incident.event_count,
            duration_seconds=incident.duration_seconds,
            first_seen=incident.first_seen,
            last_seen=incident.last_seen,
            attack_stages=incident.attack_stages,
        )

        report.executive_summary = self._build_executive_summary(incident)
        report.timeline_narrative = self._build_timeline(incident)
        report.impact_assessment = self._build_impact(incident)
        report.technical_details = self._build_technical_details(incident)
        report.iocs = self._extract_iocs(incident)
        report.response_actions = self._build_response_actions(incident)
        report.mitre_techniques = self._map_mitre(incident)
        report.affected_assets = list(incident.destination_ips)

        return report

    def _build_executive_summary(self, incident: Incident) -> str:
        """Generate an executive summary."""
        primary_category = incident.attack_categories[0] if incident.attack_categories else "unknown"
        description = CATEGORY_DESCRIPTIONS.get(
            primary_category, f"suspicious activity categorized as {primary_category}"
        )

        src_count = len(incident.source_ips)
        dst_count = len(incident.destination_ips)
        src_str = incident.source_ips[0] if src_count == 1 else f"{src_count} source IPs"

        duration = self._format_duration(incident.duration_seconds)

        summary = (
            f"A {incident.severity.value}-severity incident was detected involving "
            f"{description}. The activity originated from {src_str} and targeted "
            f"{dst_count} internal host{'s' if dst_count > 1 else ''} over a period of {duration}. "
            f"A total of {incident.event_count} related events were correlated into this incident."
        )

        if len(incident.attack_stages) >= 2:
            stages = " → ".join(s.replace("_", " ").title() for s in incident.attack_stages)
            summary += (
                f" The attack follows a multi-stage pattern ({stages}), "
                f"indicating a coordinated and potentially advanced threat."
            )

        return summary

    def _build_timeline(self, incident: Incident) -> str:
        """Build a chronological timeline narrative from sample events."""
        if not incident.sample_events:
            return "No timeline data available."

        lines = []
        for sample in incident.sample_events:
            ts = sample.get("timestamp", "Unknown time")
            name = sample.get("event_name", "Unknown event")
            src = sample.get("src_ip", "unknown")
            dst = sample.get("dst_ip", "unknown")
            port = sample.get("dst_port", "unknown")
            category = sample.get("attack_category", "unknown")

            lines.append(
                f"**{ts}** — {name} detected from {src} to {dst}:{port} "
                f"(category: {category})"
            )

        # Add context
        if incident.first_seen and incident.last_seen:
            duration = self._format_duration(incident.duration_seconds)
            lines.append(
                f"\nThe incident spanned {duration} with an average rate of "
                f"{incident.events_per_minute:.1f} events per minute."
            )

        return "\n\n".join(lines)

    def _build_impact(self, incident: Incident) -> str:
        """Assess potential impact based on attack type and scope."""
        impacts = []
        categories = set(incident.attack_categories)

        if "brute_force" in categories or "web_attack_bruteforce" in categories:
            impacts.append(
                "Potential unauthorized access to user accounts and sensitive data. "
                "If any attempts succeeded, the attacker may have access to internal systems."
            )
        if "ddos" in categories or "dos" in categories:
            impacts.append(
                "Service availability may be degraded or disrupted for legitimate users. "
                "Business operations depending on targeted services could be affected."
            )
        if "web_attack_sql" in categories:
            impacts.append(
                "Potential database compromise. If successful, the attacker may have "
                "extracted, modified, or deleted database records, including sensitive "
                "customer or business data."
            )
        if "web_attack_xss" in categories:
            impacts.append(
                "Potential session hijacking and credential theft from web application users. "
                "Stored XSS could affect all users who visit the compromised page."
            )
        if "infiltration" in categories:
            impacts.append(
                "Evidence of unauthorized internal network access. Affected systems may "
                "have been used for data exfiltration, lateral movement, or establishing persistence."
            )
        if "botnet" in categories:
            impacts.append(
                "One or more internal hosts may be compromised and under external control. "
                "These systems could be used for DDoS attacks, spam, cryptocurrency mining, "
                "or as pivot points for further network compromise."
            )
        if "port_scan" in categories:
            impacts.append(
                "Network reconnaissance indicates an adversary is mapping the attack surface. "
                "This is typically a precursor to targeted exploitation attempts."
            )
        if "heartbleed" in categories:
            impacts.append(
                "Critical vulnerability exploitation that may have exposed private keys, "
                "session tokens, passwords, and other sensitive data from server memory."
            )

        if not impacts:
            impacts.append(
                "Suspicious activity detected that warrants investigation. "
                "Full impact assessment requires manual review of affected systems."
            )

        n_targets = len(incident.destination_ips)
        targets_str = ", ".join(incident.destination_ips[:5])
        if n_targets > 5:
            targets_str += f", and {n_targets - 5} more"

        impacts.append(f"\n**Affected assets:** {targets_str}")
        impacts.append(f"**Target ports:** {', '.join(str(p) for p in incident.target_ports[:10])}")

        return "\n\n".join(impacts)

    def _build_technical_details(self, incident: Incident) -> str:
        """Generate technical analysis details."""
        sections = []

        # Attack vector analysis
        categories = incident.attack_categories
        if categories:
            cat_str = ", ".join(c.replace("_", " ").title() for c in categories)
            sections.append(f"**Attack vectors observed:** {cat_str}")

        # Kill chain progression
        if len(incident.attack_stages) >= 2:
            stages_str = " → ".join(s.replace("_", " ").title() for s in incident.attack_stages)
            sections.append(
                f"**Kill chain progression:** {stages_str}\n"
                f"The multi-stage nature of this attack suggests a deliberate, "
                f"coordinated operation rather than opportunistic scanning."
            )

        # Volume analysis
        rate = incident.events_per_minute
        if rate > 100:
            sections.append(
                f"**Volume analysis:** {rate:.0f} events/minute indicates automated tooling. "
                f"The high rate suggests the use of attack frameworks such as Hydra, "
                f"Medusa, or custom scripts."
            )
        elif rate > 10:
            sections.append(
                f"**Volume analysis:** {rate:.1f} events/minute suggests semi-automated "
                f"or scripted attack activity."
            )

        # Source analysis
        src_count = len(incident.source_ips)
        if src_count > 3:
            sections.append(
                f"**Source distribution:** {src_count} distinct source IPs observed, "
                f"indicating a distributed attack or the use of proxies/VPN."
            )
        elif src_count == 1:
            sections.append(
                f"**Source analysis:** Single source IP ({incident.source_ips[0]}) "
                f"suggests a focused, targeted attack from a single threat actor."
            )

        return "\n\n".join(sections) if sections else "No additional technical details available."

    def _extract_iocs(self, incident: Incident) -> list[IoC]:
        """Extract Indicators of Compromise from the incident."""
        iocs = []

        # Source IPs
        for ip in incident.source_ips:
            iocs.append(IoC(
                type="ip",
                value=ip,
                context="Source of attack traffic",
                action="block" if incident.severity in (IncidentSeverity.CRITICAL, IncidentSeverity.HIGH) else "monitor",
            ))

        # Target ports
        for port in incident.target_ports:
            iocs.append(IoC(
                type="port",
                value=str(port),
                context=f"Targeted service port",
                action="investigate",
            ))

        # Signatures from attack categories
        for category in incident.attack_categories:
            if category not in ("benign", "unknown"):
                iocs.append(IoC(
                    type="signature",
                    value=f"ALERT-{category.upper()}",
                    context=f"Attack pattern: {category.replace('_', ' ')}",
                    action="monitor",
                ))

        return iocs

    def _build_response_actions(self, incident: Incident) -> list[ResponseAction]:
        """Build prioritized response actions based on severity."""
        templates = RESPONSE_TEMPLATES.get(incident.severity, RESPONSE_TEMPLATES[IncidentSeverity.LOW])

        actions = []
        for template in templates:
            action_text = template["action"]

            # Customize with actual incident data
            if incident.source_ips and "source IP" in action_text.lower():
                ips = ", ".join(incident.source_ips[:5])
                action_text = action_text.replace("source IPs", f"source IPs ({ips})")

            actions.append(ResponseAction(
                priority=template["priority"],
                action=action_text,
                rationale=template.get("rationale", ""),
            ))

        return actions

    def _map_mitre(self, incident: Incident) -> list[str]:
        """Map attack categories to MITRE ATT&CK techniques."""
        techniques: list[str] = []
        seen: set[str] = set()
        for category in incident.attack_categories:
            for technique in CATEGORY_TO_MITRE.get(category, []):
                if technique not in seen:
                    techniques.append(technique)
                    seen.add(technique)
        return techniques

    @staticmethod
    def _format_duration(seconds: float) -> str:
        if seconds <= 0:
            return "less than a second"
        if seconds < 60:
            return f"{int(seconds)} seconds"
        mins = int(seconds // 60)
        if mins < 60:
            return f"{mins} minutes"
        hours = mins // 60
        remaining_mins = mins % 60
        return f"{hours} hours and {remaining_mins} minutes"
