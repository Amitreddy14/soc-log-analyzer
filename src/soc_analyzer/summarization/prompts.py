"""Prompt engineering for incident summarization.

Constructs structured prompts that give the LLM everything it needs to
generate an accurate, actionable incident report. The prompt includes:
    - System role (SOC analyst persona)
    - Incident metadata and statistics
    - Sample events (evidence)
    - Output format specification (JSON)

Prompt design follows best practices:
    - Clear role definition
    - Structured input data
    - Explicit output schema
    - Few-shot examples for consistency
"""

from __future__ import annotations

import json
from typing import Any

from soc_analyzer.correlation.incidents import Incident

SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst with 10+ years of experience in threat detection, incident response, and forensic analysis. You work at a Fortune 500 company and are responsible for analyzing security incidents detected by the SIEM.

Your task is to analyze a correlated security incident and produce a structured incident report. Be specific, technical, and actionable. Do not use vague language — every recommendation must be concrete enough for a junior analyst to execute.

You must respond ONLY with a valid JSON object matching the schema provided. No markdown, no preamble, no explanation outside the JSON."""

ANALYSIS_PROMPT_TEMPLATE = """Analyze the following security incident and generate a structured report.

## Incident Data

**Incident ID:** {incident_id}
**Severity:** {severity}
**Event Count:** {event_count}
**Duration:** {duration}
**First Seen:** {first_seen}
**Last Seen:** {last_seen}

**Source IPs:** {source_ips}
**Destination IPs:** {destination_ips}
**Target Ports:** {target_ports}

**Attack Categories:** {attack_categories}
**Attack Stages (Kill Chain):** {attack_stages}

**Severity Breakdown:**
{severity_breakdown}

## Sample Events (Evidence)

{sample_events}

## Required Output Schema

Respond with a JSON object containing these exact keys:

{{
    "executive_summary": "2-3 sentence summary of what happened, suitable for a CISO briefing",
    "timeline_narrative": "Chronological narrative of the attack progression",
    "impact_assessment": "What systems/data are at risk and potential business impact",
    "technical_details": "Technical analysis of the attack vectors and methods used",
    "iocs": [
        {{
            "type": "ip|port|signature",
            "value": "the indicator",
            "context": "why this is suspicious",
            "action": "block|monitor|investigate"
        }}
    ],
    "response_actions": [
        {{
            "priority": 1,
            "action": "specific action to take",
            "rationale": "why this is important"
        }}
    ],
    "mitre_techniques": ["T1110 - Brute Force", "T1046 - Network Service Scanning"]
}}"""


def build_prompt(incident: Incident) -> tuple[str, str]:
    """Build system and user prompts from an Incident.

    Returns:
        Tuple of (system_prompt, user_prompt).
    """
    # Format severity breakdown
    severity_lines = []
    for sev, count in sorted(incident.severity_counts.items()):
        severity_lines.append(f"  - {sev.upper()}: {count}")
    severity_breakdown = "\n".join(severity_lines) if severity_lines else "  No data"

    # Format sample events
    event_lines = []
    for i, sample in enumerate(incident.sample_events[:5], 1):
        event_lines.append(
            f"Event {i}:\n"
            f"  Timestamp: {sample.get('timestamp', 'N/A')}\n"
            f"  Name: {sample.get('event_name', 'N/A')}\n"
            f"  Severity: {sample.get('severity', 'N/A')}\n"
            f"  Source IP: {sample.get('src_ip', 'N/A')}\n"
            f"  Dest IP: {sample.get('dst_ip', 'N/A')}\n"
            f"  Dest Port: {sample.get('dst_port', 'N/A')}\n"
            f"  Category: {sample.get('attack_category', 'N/A')}"
        )
    sample_events_str = "\n\n".join(event_lines) if event_lines else "No sample events available"

    # Format duration
    duration_secs = incident.duration_seconds
    if duration_secs > 3600:
        duration = f"{duration_secs / 3600:.1f} hours"
    elif duration_secs > 60:
        duration = f"{duration_secs / 60:.1f} minutes"
    else:
        duration = f"{duration_secs:.0f} seconds"

    user_prompt = ANALYSIS_PROMPT_TEMPLATE.format(
        incident_id=incident.id,
        severity=incident.severity.value.upper(),
        event_count=incident.event_count,
        duration=duration,
        first_seen=incident.first_seen.isoformat() if incident.first_seen else "N/A",
        last_seen=incident.last_seen.isoformat() if incident.last_seen else "N/A",
        source_ips=", ".join(incident.source_ips) or "N/A",
        destination_ips=", ".join(incident.destination_ips) or "N/A",
        target_ports=", ".join(str(p) for p in incident.target_ports) or "N/A",
        attack_categories=", ".join(incident.attack_categories) or "N/A",
        attack_stages=" → ".join(incident.attack_stages) or "N/A",
        severity_breakdown=severity_breakdown,
        sample_events=sample_events_str,
    )

    return SYSTEM_PROMPT, user_prompt


def parse_llm_response(response_text: str) -> dict[str, Any]:
    """Parse the LLM's JSON response, handling common formatting issues.

    LLMs sometimes wrap JSON in markdown code fences or add preamble text.
    This function handles those edge cases.
    """
    text = response_text.strip()

    # Remove markdown code fences
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first line (```json) and last line (```)
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines)

    # Try to find JSON object
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        text = text[start:end]

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        return {"error": f"Failed to parse LLM response: {e}", "raw": response_text}
