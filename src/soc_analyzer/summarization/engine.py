"""Summarization engine — orchestrates report generation for incidents.

Manages the lifecycle of generating reports for all incidents:
    1. Selects the summarizer (LLM or template based on config)
    2. Generates reports for each incident (prioritizing critical/high)
    3. Outputs reports as Markdown, JSON, or rich console output

Usage:
    engine = SummarizationEngine(provider="openai")
    reports = engine.summarize_all(incidents)
    engine.print_reports(reports)
    engine.save_reports(reports, "reports/")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from soc_analyzer.correlation.incidents import Incident, IncidentSeverity
from soc_analyzer.summarization.llm import LLMSummarizer
from soc_analyzer.summarization.report import IncidentReport
from soc_analyzer.summarization.template import TemplateSummarizer
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


class SummarizationEngine:
    """Orchestrates incident report generation."""

    def __init__(
        self,
        provider: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        """Initialize the summarization engine.

        Args:
            provider: LLM provider ("openai", "anthropic", or None for template-only).
            model: Specific model name. Uses provider default if None.
            api_key: API key. Falls back to environment variable if None.
        """
        self.provider = provider
        if provider:
            self._summarizer = LLMSummarizer(
                provider=provider, model=model, api_key=api_key
            )
        else:
            self._summarizer = TemplateSummarizer()

        self._reports: list[IncidentReport] = []

    def summarize(self, incident: Incident) -> IncidentReport:
        """Generate a report for a single incident."""
        report = self._summarizer.summarize(incident)
        self._reports.append(report)
        return report

    def summarize_all(
        self,
        incidents: list[Incident],
        max_reports: int | None = None,
    ) -> list[IncidentReport]:
        """Generate reports for all incidents.

        Processes critical/high severity incidents first.

        Args:
            incidents: List of correlated incidents.
            max_reports: Maximum number of reports to generate (None = all).

        Returns:
            List of generated IncidentReport objects.
        """
        # Sort by severity (critical first)
        severity_order = {
            IncidentSeverity.CRITICAL: 0,
            IncidentSeverity.HIGH: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.LOW: 3,
            IncidentSeverity.INFO: 4,
        }
        sorted_incidents = sorted(
            incidents, key=lambda i: severity_order.get(i.severity, 5)
        )

        if max_reports:
            sorted_incidents = sorted_incidents[:max_reports]

        logger.info("summarizing_incidents", count=len(sorted_incidents))
        console.print(f"\n[bold]Generating reports for {len(sorted_incidents)} incidents...[/]")

        reports = []
        for incident in sorted_incidents:
            report = self.summarize(incident)
            reports.append(report)
            sev_style = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(
                report.severity, "green"
            )
            console.print(
                f"  [{sev_style}]●[/] {report.incident_id[:16]} "
                f"[{sev_style}]{report.severity.upper()}[/] — {report.title[:60]}"
            )

        return reports

    def print_reports(self, reports: list[IncidentReport] | None = None) -> None:
        """Print reports as formatted Markdown in the console."""
        reports = reports or self._reports

        for report in reports:
            md_content = report.to_markdown()
            console.print(Panel(
                Markdown(md_content),
                title=f"[bold]{report.incident_id}[/]",
                border_style="red" if report.severity == "critical" else "yellow",
                expand=True,
            ))
            console.print()

    def save_reports(
        self,
        reports: list[IncidentReport] | None = None,
        output_dir: str | Path = "reports",
        format: str = "markdown",
    ) -> list[Path]:
        """Save reports to files.

        Args:
            reports: Reports to save (uses internal cache if None).
            output_dir: Directory to save reports to.
            format: "markdown" or "json".

        Returns:
            List of saved file paths.
        """
        reports = reports or self._reports
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        saved_paths = []
        for report in reports:
            safe_id = report.incident_id.replace("-", "_")

            if format == "json":
                filepath = output_dir / f"{safe_id}.json"
                with open(filepath, "w") as f:
                    json.dump(report.model_dump(mode="json"), f, indent=2, default=str)
            else:
                filepath = output_dir / f"{safe_id}.md"
                filepath.write_text(report.to_markdown(), encoding="utf-8")

            saved_paths.append(filepath)

        logger.info("reports_saved", count=len(saved_paths), directory=str(output_dir))
        console.print(
            f"\n[green]✓[/] {len(saved_paths)} reports saved to {output_dir}/ ({format})"
        )
        return saved_paths

    def print_summary_table(self, reports: list[IncidentReport] | None = None) -> None:
        """Print a summary table of all generated reports."""
        reports = reports or self._reports

        table = Table(title="Generated Incident Reports")
        table.add_column("Incident ID", style="dim")
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Events", justify="right")
        table.add_column("IoCs", justify="right")
        table.add_column("Actions", justify="right")
        table.add_column("Generator")

        for report in reports:
            sev_style = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(
                report.severity, "green"
            )
            table.add_row(
                report.incident_id[:16],
                f"[{sev_style}]{report.severity.upper()}[/]",
                report.title[:50],
                str(report.event_count),
                str(len(report.iocs)),
                str(len(report.response_actions)),
                report.generator,
            )

        console.print(table)
