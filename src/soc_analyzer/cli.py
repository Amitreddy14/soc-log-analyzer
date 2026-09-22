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


<<<<<<< HEAD
@main.command()
@click.option(
    "--model-type", "-m",
    type=click.Choice(["random_forest", "gradient_boosting"]),
    default="gradient_boosting",
    help="Model type to train.",
)
@click.option("--tune", is_flag=True, help="Run hyperparameter tuning (slower).")
@click.option(
    "--output", "-o",
    type=click.Path(),
    default="models/severity_v1",
    help="Directory to save the trained model.",
)
@click.option("--csv", type=click.Path(exists=True), default=None, help="Train from CSV instead of DB.")
def train(model_type: str, tune: bool, output: str, csv: str | None) -> None:
    """Train the severity classification model."""
    from soc_analyzer.ml.training import ModelTrainer
    from soc_analyzer.ml.evaluation import EvaluationReport

    trainer = ModelTrainer()

    if csv:
        split_info = trainer.load_data_from_csv(csv)
    else:
        split_info = trainer.load_data_from_db(settings.db.path)

    console.print(f"\n[bold]Data loaded:[/] {split_info['total']:,} events "
                  f"(train={split_info['train']:,}, val={split_info['validation']:,}, test={split_info['test']:,})")

    metrics = trainer.train(model_type=model_type, tune_hyperparams=tune)
    trainer.save(output)

    report = EvaluationReport(trainer)
    report.print_summary()
    report.save_report(output)

    console.print(f"\n[green]✓[/] Model saved to {output}/")


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--model", "-m",
    type=click.Path(exists=True),
    default="models/severity_v1",
    help="Path to saved model directory.",
)
@click.option(
    "--source", "-s",
    type=click.Choice([s.value for s in LogSource], case_sensitive=False),
    default=None,
)
def predict(path: str, model: str, source: str | None) -> None:
    """Classify events in a log file using a trained model."""
    from soc_analyzer.ml.classifier import SeverityClassifier
    from soc_analyzer.ingestion.pipeline import IngestionPipeline

    classifier = SeverityClassifier.from_saved(model)
    console.print(f"[cyan]Model loaded:[/] {classifier.model_info['model_type']}")

    # Ingest the file
    source_type = LogSource(source) if source else None
    pipeline = IngestionPipeline(db_path=":memory:")
    pipeline.start()

    parser = pipeline.get_parser(
        source_type or pipeline.detect_source_type(Path(path))
    )

    events = list(parser.parse_and_normalize(Path(path)))
    console.print(f"[cyan]Parsed:[/] {len(events)} events")

    # Classify
    classified = classifier.classify_batch(events)

    # Summary
    from collections import Counter
    severity_counts = Counter(e.predicted_severity.value for e in classified)
    console.print("\n[bold]Prediction Summary:[/]")
    for sev in ["critical", "high", "medium", "low", "benign"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            style = {"critical": "red", "high": "yellow", "medium": "cyan"}.get(sev, "green")
            console.print(f"  [{style}]{sev.upper():>10}[/]: {count:,}")

    avg_conf = sum(e.confidence or 0 for e in classified) / max(len(classified), 1)
    console.print(f"\n  Avg confidence: {avg_conf:.3f}")

    pipeline.stop()


=======
>>>>>>> f3ff8a7cee430653e81beda3f327259db5a6d364
if __name__ == "__main__":
    main()
