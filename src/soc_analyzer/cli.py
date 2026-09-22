"""Command-line interface for the SOC Log Analyzer.

Usage:
    soc-analyzer ingest <file_or_dir> [--source firewall|cicids|syslog|auth]
    soc-analyzer stats
    soc-analyzer generate-samples
"""

from __future__ import annotations

from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

from soc_analyzer.config import settings
from soc_analyzer.models.schemas import LogSource
from soc_analyzer.utils.logger import setup_logging

console = Console()


@click.group()
@click.version_option(package_name="soc-log-analyzer")
def main() -> None:
    """SOC Log Analyzer — LLM-powered security log triage and correlation."""
    setup_logging()


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--source", "-s",
    type=click.Choice([s.value for s in LogSource], case_sensitive=False),
    default=None,
    help="Force a specific source type (auto-detected if omitted).",
)
@click.option("--batch-size", "-b", type=int, default=None, help="Batch size for DB inserts.")
def ingest(path: str, source: str | None, batch_size: int | None) -> None:
    """Ingest log files from a file or directory."""
    from soc_analyzer.ingestion.pipeline import IngestionPipeline

    source_type = LogSource(source) if source else None
    target = Path(path)

    pipeline = IngestionPipeline()
    pipeline.start()

    try:
        if target.is_dir():
            pipeline.ingest_directory(target, source_type=source_type)
        else:
            pipeline.ingest_file(target, source_type=source_type, batch_size=batch_size)
    finally:
        pipeline.stop()


@main.command()
def stats() -> None:
    """Show statistics about ingested events."""
    from soc_analyzer.ingestion.pipeline import IngestionPipeline
    from rich.table import Table

    pipeline = IngestionPipeline()
    pipeline.start()

    try:
        summary = pipeline.get_store_summary()

        console.print(Panel(
            f"[bold green]{summary['total_events']:,}[/] total events",
            title="Event Store",
        ))

        if summary["by_severity"]:
            table = Table(title="By Severity")
            table.add_column("Severity", style="bold")
            table.add_column("Count", justify="right")
            for sev, count in summary["by_severity"].items():
                style = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(sev, "")
                table.add_row(sev, f"{count:,}", style=style)
            console.print(table)

        if summary["by_attack_category"]:
            table = Table(title="By Attack Category")
            table.add_column("Category", style="bold")
            table.add_column("Count", justify="right")
            for cat, count in summary["by_attack_category"].items():
                table.add_row(cat, f"{count:,}")
            console.print(table)

    finally:
        pipeline.stop()


@main.command(name="generate-samples")
@click.option("--count", "-n", type=int, default=500, help="Number of events per source type.")
def generate_samples(count: int) -> None:
    """Generate synthetic sample log files for testing."""
    from scripts.generate_synthetic import generate_all_samples
    settings.ensure_dirs()
    generate_all_samples(output_dir=settings.sample_data_dir, count=count)
    console.print(f"[green]✓[/] Sample files generated in {settings.sample_data_dir}")


if __name__ == "__main__":
    main()
