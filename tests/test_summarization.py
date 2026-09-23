"""Tests for the incident summarization pipeline.

Covers: template summarizer, prompt building, report generation,
Markdown rendering, and the summarization engine.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from soc_analyzer.correlation.incidents import Incident, IncidentSeverity
from soc_analyzer.models.schemas import (
    AttackCategory,
    LogSource,
    NormalizedLogEvent,
    SeverityLevel,
)
from soc_analyzer.summarization.engine import SummarizationEngine
from soc_analyzer.summarization.prompts import build_prompt, parse_llm_response
from soc_analyzer.summarization.report import IncidentReport, IoC, ResponseAction
from soc_analyzer.summarization.template import TemplateSummarizer


def _make_event(
    src_ip: str = "91.240.118.172",
    dst_ip: str = "10.0.0.5",
    dst_port: int = 22,
    severity: SeverityLevel = SeverityLevel.HIGH,
    attack_category: AttackCategory = AttackCategory.BRUTE_FORCE,
    timestamp: datetime | None = None,
    **kwargs,
) -> NormalizedLogEvent:
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


def _make_incident(multi_stage: bool = False) -> Incident:
    """Create a realistic test incident."""
    base = datetime(2024, 1, 15, 14, 30, 0)
    incident = Incident()

    if multi_stage:
        # Port scan phase
        for i in range(5):
            incident.add_event(_make_event(
                attack_category=AttackCategory.PORT_SCAN,
                severity=SeverityLevel.MEDIUM,
                dst_port=22 + i,
                timestamp=base + timedelta(seconds=i * 10),
            ))
        # Brute force phase
        for i in range(10):
            incident.add_event(_make_event(
                attack_category=AttackCategory.BRUTE_FORCE,
                severity=SeverityLevel.HIGH,
                timestamp=base + timedelta(minutes=2, seconds=i * 5),
            ))
        # Infiltration
        incident.add_event(_make_event(
            attack_category=AttackCategory.INFILTRATION,
            severity=SeverityLevel.CRITICAL,
            timestamp=base + timedelta(minutes=5),
        ))
    else:
        for i in range(20):
            incident.add_event(_make_event(
                timestamp=base + timedelta(seconds=i * 3),
            ))

    incident.generate_title()
    return incident


class TestIncidentReport:
    """Test the IncidentReport data model."""

    def test_to_markdown_contains_sections(self) -> None:
        report = IncidentReport(
            incident_id="INC-TEST001",
            severity="critical",
            title="Test Incident",
            executive_summary="This is a test summary.",
            timeline_narrative="Event 1 happened, then event 2.",
            impact_assessment="Systems are at risk.",
            iocs=[IoC(type="ip", value="1.2.3.4", context="Attacker", action="block")],
            response_actions=[ResponseAction(priority=1, action="Block IP", rationale="Active threat")],
            mitre_techniques=["T1110 - Brute Force"],
        )
        md = report.to_markdown()

        assert "# Incident Report: INC-TEST001" in md
        assert "Executive Summary" in md
        assert "This is a test summary." in md
        assert "Timeline" in md
        assert "Impact Assessment" in md
        assert "Indicators of Compromise" in md
        assert "`1.2.3.4`" in md
        assert "Recommended Response Actions" in md
        assert "IMMEDIATE" in md
        assert "MITRE ATT&CK" in md
        assert "T1110" in md

    def test_to_markdown_skips_empty_sections(self) -> None:
        report = IncidentReport(
            incident_id="INC-MINIMAL",
            severity="low",
            title="Minimal",
            executive_summary="Just a summary.",
        )
        md = report.to_markdown()
        assert "Timeline" not in md
        assert "Impact Assessment" not in md

    def test_duration_formatting(self) -> None:
        report = IncidentReport(
            incident_id="INC-DUR", severity="low", title="Test",
            duration_seconds=3725,
        )
        md = report.to_markdown()
        assert "1h 2m" in md


class TestTemplateSummarizer:
    """Test the template-based summarizer."""

    def test_generates_complete_report(self) -> None:
        summarizer = TemplateSummarizer()
        incident = _make_incident()
        report = summarizer.summarize(incident)

        assert report.incident_id == incident.id
        assert report.severity == incident.severity.value
        assert report.generator == "template"
        assert len(report.executive_summary) > 50
        assert len(report.timeline_narrative) > 0
        assert len(report.impact_assessment) > 0
        assert len(report.iocs) > 0
        assert len(report.response_actions) > 0

    def test_multi_stage_report(self) -> None:
        summarizer = TemplateSummarizer()
        incident = _make_incident(multi_stage=True)
        report = summarizer.summarize(incident)

        assert "multi-stage" in report.executive_summary.lower() or "coordinated" in report.executive_summary.lower()
        assert len(report.mitre_techniques) >= 2

    def test_mitre_mapping(self) -> None:
        summarizer = TemplateSummarizer()
        incident = _make_incident()
        report = summarizer.summarize(incident)

        assert any("T1110" in t for t in report.mitre_techniques)

    def test_iocs_contain_attacker_ip(self) -> None:
        summarizer = TemplateSummarizer()
        incident = _make_incident()
        report = summarizer.summarize(incident)

        ip_iocs = [ioc for ioc in report.iocs if ioc.type == "ip"]
        assert any(ioc.value == "91.240.118.172" for ioc in ip_iocs)

    def test_critical_severity_has_immediate_actions(self) -> None:
        summarizer = TemplateSummarizer()
        incident = _make_incident(multi_stage=True)
        report = summarizer.summarize(incident)

        immediate_actions = [a for a in report.response_actions if a.priority == 1]
        assert len(immediate_actions) >= 1

    def test_response_actions_sorted_by_priority(self) -> None:
        summarizer = TemplateSummarizer()
        incident = _make_incident(multi_stage=True)
        report = summarizer.summarize(incident)
        md = report.to_markdown()

        # IMMEDIATE should appear before STANDARD
        immediate_pos = md.find("IMMEDIATE")
        standard_pos = md.find("STANDARD")
        if immediate_pos >= 0 and standard_pos >= 0:
            assert immediate_pos < standard_pos

    def test_different_attack_types(self) -> None:
        """Test summarization for various attack categories."""
        summarizer = TemplateSummarizer()

        for category in [
            AttackCategory.DDOS,
            AttackCategory.WEB_ATTACK_SQL,
            AttackCategory.BOTNET,
            AttackCategory.PORT_SCAN,
        ]:
            incident = Incident()
            base = datetime(2024, 1, 1, 10, 0, 0)
            for i in range(5):
                incident.add_event(_make_event(
                    attack_category=category,
                    severity=SeverityLevel.HIGH,
                    timestamp=base + timedelta(seconds=i),
                ))
            incident.generate_title()

            report = summarizer.summarize(incident)
            assert len(report.executive_summary) > 0
            assert len(report.impact_assessment) > 0


class TestPromptBuilder:
    """Test prompt construction for LLM summarization."""

    def test_build_prompt_returns_two_strings(self) -> None:
        incident = _make_incident()
        system_prompt, user_prompt = build_prompt(incident)

        assert isinstance(system_prompt, str)
        assert isinstance(user_prompt, str)
        assert len(system_prompt) > 100
        assert len(user_prompt) > 200

    def test_prompt_contains_incident_data(self) -> None:
        incident = _make_incident()
        _, user_prompt = build_prompt(incident)

        assert incident.id in user_prompt
        assert "91.240.118.172" in user_prompt
        assert "brute_force" in user_prompt.lower()

    def test_prompt_contains_output_schema(self) -> None:
        incident = _make_incident()
        _, user_prompt = build_prompt(incident)

        assert "executive_summary" in user_prompt
        assert "response_actions" in user_prompt
        assert "mitre_techniques" in user_prompt

    def test_parse_valid_json(self) -> None:
        response = '{"executive_summary": "Test", "iocs": [], "response_actions": []}'
        parsed = parse_llm_response(response)
        assert parsed["executive_summary"] == "Test"

    def test_parse_json_with_code_fences(self) -> None:
        response = '```json\n{"executive_summary": "Test"}\n```'
        parsed = parse_llm_response(response)
        assert parsed["executive_summary"] == "Test"

    def test_parse_json_with_preamble(self) -> None:
        response = 'Here is the analysis:\n\n{"executive_summary": "Test"}'
        parsed = parse_llm_response(response)
        assert parsed["executive_summary"] == "Test"

    def test_parse_invalid_json(self) -> None:
        parsed = parse_llm_response("this is not json at all")
        assert "error" in parsed


class TestSummarizationEngine:
    """Test the summarization engine."""

    def test_template_mode(self) -> None:
        engine = SummarizationEngine(provider=None)
        incident = _make_incident()
        report = engine.summarize(incident)

        assert report.generator == "template"
        assert report.incident_id == incident.id

    def test_summarize_all(self) -> None:
        engine = SummarizationEngine(provider=None)
        incidents = [_make_incident(), _make_incident(multi_stage=True)]
        reports = engine.summarize_all(incidents)

        assert len(reports) == 2

    def test_summarize_with_max_reports(self) -> None:
        engine = SummarizationEngine(provider=None)
        incidents = [_make_incident() for _ in range(5)]
        reports = engine.summarize_all(incidents, max_reports=2)

        assert len(reports) == 2

    def test_save_reports_markdown(self, tmp_path: Path) -> None:
        engine = SummarizationEngine(provider=None)
        incident = _make_incident()
        reports = [engine.summarize(incident)]

        saved = engine.save_reports(reports, output_dir=tmp_path, format="markdown")
        assert len(saved) == 1
        assert saved[0].suffix == ".md"
        assert saved[0].exists()
        content = saved[0].read_text()
        assert "Incident Report" in content

    def test_save_reports_json(self, tmp_path: Path) -> None:
        engine = SummarizationEngine(provider=None)
        incident = _make_incident()
        reports = [engine.summarize(incident)]

        saved = engine.save_reports(reports, output_dir=tmp_path, format="json")
        assert len(saved) == 1
        assert saved[0].suffix == ".json"
        import json
        data = json.loads(saved[0].read_text())
        assert "executive_summary" in data

    def test_llm_mode_falls_back_without_key(self) -> None:
        """Without an API key, LLM mode should fall back to template."""
        engine = SummarizationEngine(provider="openai")
        incident = _make_incident()
        report = engine.summarize(incident)

        # Should fall back to template since no API key is set
        assert report.generator == "template"
        assert len(report.executive_summary) > 0
