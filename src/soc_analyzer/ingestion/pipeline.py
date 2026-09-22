"""Ingestion pipeline — orchestrates parsing, normalization, and storage.

This is the main entry point for getting data into the system. It:
1. Auto-detects the log source type from file patterns
2. Routes to the correct parser
3. Batches normalized events for efficient DB inserts
4. Tracks ingestion stats for observability
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from tqdm import tqdm

from soc_analyzer.config import settings
from soc_analyzer.ingestion.parsers import (
    AuthLogParser,
    BaseParser,
    CICIDSParser,
    FirewallLogParser,
    SyslogParser,
)
from soc_analyzer.models.schemas import LogSource, NormalizedLogEvent
from soc_analyzer.storage.database import EventStore
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()

# Map source types to parser classes
PARSER_REGISTRY: dict[LogSource, type[BaseParser]] = {
    LogSource.CICIDS: CICIDSParser,
    LogSource.FIREWALL: FirewallLogParser,
    LogSource.SYSLOG: SyslogParser,
    LogSource.AUTH: AuthLogParser,
}

# File pattern → source type heuristics
FILE_PATTERNS: list[tuple[str, LogSource]] = [
    ("cicids", LogSource.CICIDS),
    ("friday", LogSource.CICIDS),       # CICIDS day-based filenames
    ("monday", LogSource.CICIDS),
    ("tuesday", LogSource.CICIDS),
    ("wednesday", LogSource.CICIDS),
    ("thursday", LogSource.CICIDS),
    ("firewall", LogSource.FIREWALL),
    ("iptables", LogSource.FIREWALL),
    ("panos", LogSource.FIREWALL),
    ("auth", LogSource.AUTH),
    ("secure", LogSource.AUTH),
    ("syslog", LogSource.SYSLOG),
]


class IngestionPipeline:
    """Orchestrates log ingestion from multiple sources."""

    def __init__(self, db_path: str | None = None) -> None:
        self.store = EventStore(db_path or settings.db.path)
        self._run_stats: list[dict[str, Any]] = []

    def start(self) -> None:
        """Initialize the pipeline (connect to DB)."""
        self.store.connect()
        logger.info("pipeline_started")

    def stop(self) -> None:
        """Shutdown the pipeline."""
        self.store.close()
        logger.info("pipeline_stopped")

    def detect_source_type(self, filepath: Path) -> LogSource | None:
        """Auto-detect log source type from filename."""
        name_lower = filepath.name.lower()
        for pattern, source in FILE_PATTERNS:
            if pattern in name_lower:
                return source
        return None

    def get_parser(self, source_type: LogSource) -> BaseParser:
        """Get the appropriate parser for a source type."""
        parser_cls = PARSER_REGISTRY.get(source_type)
        if not parser_cls:
            raise ValueError(f"No parser registered for source type: {source_type}")
        return parser_cls()

    def ingest_file(
        self,
        filepath: str | Path,
        source_type: LogSource | None = None,
        batch_size: int | None = None,
        show_progress: bool = True,
    ) -> dict[str, Any]:
        """Ingest a single log file into the event store.

        Args:
            filepath: Path to the log file.
            source_type: Explicit source type (auto-detected if None).
            batch_size: Events per DB insert batch.
            show_progress: Show tqdm progress bar.

        Returns:
            Ingestion statistics dict.
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        batch_size = batch_size or settings.ingestion.batch_size
        started = datetime.now()

        # Detect or use provided source type
        if source_type is None:
            source_type = self.detect_source_type(filepath)
            if source_type is None:
                raise ValueError(
                    f"Cannot auto-detect source type for {filepath.name}. "
                    f"Please specify source_type explicitly."
                )

        logger.info("ingesting_file", file=str(filepath), source=source_type.value)
        console.print(f"\n[bold cyan]Ingesting:[/] {filepath.name} ({source_type.value})")

        parser = self.get_parser(source_type)
        batch: list[NormalizedLogEvent] = []
        total_inserted = 0
        total_errors = 0

        event_iter = parser.parse_and_normalize(filepath)
        if show_progress:
            event_iter = tqdm(event_iter, desc="Processing", unit="events")

        for event in event_iter:
            batch.append(event)
            if len(batch) >= batch_size:
                inserted = self.store.insert_events(batch)
                total_inserted += inserted
                batch.clear()

        # Flush remaining
        if batch:
            inserted = self.store.insert_events(batch)
            total_inserted += inserted

        completed = datetime.now()
        total_errors = parser.stats["errors"]

        # Log the ingestion run
        self.store.log_ingestion(
            source_file=str(filepath),
            source_type=source_type.value,
            total=total_inserted + total_errors,
            success=total_inserted,
            failed=total_errors,
            started=started,
            completed=completed,
        )

        stats = {
            "file": filepath.name,
            "source_type": source_type.value,
            "events_ingested": total_inserted,
            "errors": total_errors,
            "duration_sec": (completed - started).total_seconds(),
            "events_per_sec": round(
                total_inserted / max((completed - started).total_seconds(), 0.001)
            ),
        }
        self._run_stats.append(stats)

        console.print(
            f"  [green]✓[/] {total_inserted:,} events ingested "
            f"({total_errors} errors) in {stats['duration_sec']:.1f}s "
            f"({stats['events_per_sec']:,} events/sec)"
        )

        return stats

    def ingest_directory(
        self,
        directory: str | Path,
        source_type: LogSource | None = None,
        recursive: bool = False,
    ) -> list[dict[str, Any]]:
        """Ingest all log files from a directory.

        Args:
            directory: Path to the directory.
            source_type: Force all files to this type (auto-detect if None).
            recursive: Search subdirectories.

        Returns:
            List of ingestion statistics for each file.
        """
        directory = Path(directory)
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        pattern = "**/*" if recursive else "*"
        files = sorted(
            f for f in directory.glob(pattern)
            if f.is_file() and f.suffix.lower() in (".csv", ".log", ".txt")
        )

        console.print(f"\n[bold]Found {len(files)} log files in {directory}[/]")

        results = []
        for filepath in files:
            try:
                stats = self.ingest_file(filepath, source_type=source_type)
                results.append(stats)
            except Exception as e:
                logger.error("file_ingestion_failed", file=str(filepath), error=str(e))
                console.print(f"  [red]✗[/] {filepath.name}: {e}")

        self._print_summary(results)
        return results

    def _print_summary(self, results: list[dict[str, Any]]) -> None:
        """Print a summary table of all ingested files."""
        if not results:
            return

        table = Table(title="\nIngestion Summary")
        table.add_column("File", style="cyan")
        table.add_column("Source", style="magenta")
        table.add_column("Events", justify="right", style="green")
        table.add_column("Errors", justify="right", style="red")
        table.add_column("Time (s)", justify="right")
        table.add_column("Rate (e/s)", justify="right")

        total_events = 0
        total_errors = 0

        for r in results:
            table.add_row(
                r["file"],
                r["source_type"],
                f"{r['events_ingested']:,}",
                str(r["errors"]),
                f"{r['duration_sec']:.1f}",
                f"{r['events_per_sec']:,}",
            )
            total_events += r["events_ingested"]
            total_errors += r["errors"]

        table.add_section()
        table.add_row(
            "[bold]TOTAL[/]", "",
            f"[bold]{total_events:,}[/]",
            f"[bold]{total_errors}[/]",
            "", "",
        )

        console.print(table)

    def get_store_summary(self) -> dict[str, Any]:
        """Get a summary of what's currently in the event store."""
        return {
            "total_events": self.store.count_events(),
            "by_severity": self.store.count_by_severity(),
            "by_attack_category": self.store.count_by_attack_category(),
            "top_source_ips": self.store.get_top_source_ips(limit=5),
        }
