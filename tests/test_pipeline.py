"""End-to-end tests for the ingestion pipeline.

These tests generate synthetic data, ingest it, and verify the full
pipeline: parsing → normalization → storage → query.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from soc_analyzer.ingestion.pipeline import IngestionPipeline
from soc_analyzer.models.schemas import LogSource

# Import generators
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from generate_synthetic import (
    generate_auth_logs,
    generate_firewall_logs,
    generate_sample_cicids,
    generate_syslog,
)


@pytest.fixture
def sample_dir(tmp_path: Path) -> Path:
    """Generate sample logs in a temp directory."""
    generate_firewall_logs(tmp_path, count=100)
    generate_auth_logs(tmp_path, count=100)
    generate_syslog(tmp_path, count=100)
    generate_sample_cicids(tmp_path, count=100)
    return tmp_path


@pytest.fixture
def pipeline(tmp_path: Path) -> IngestionPipeline:
    """Create a pipeline with a temporary database."""
    db_path = tmp_path / "test.duckdb"
    p = IngestionPipeline(db_path=str(db_path))
    p.start()
    yield p
    p.stop()


class TestSourceDetection:
    """Test auto-detection of log source types."""

    def test_detects_cicids(self, pipeline: IngestionPipeline) -> None:
        assert pipeline.detect_source_type(Path("Friday-WorkingHours.csv")) == LogSource.CICIDS

    def test_detects_firewall(self, pipeline: IngestionPipeline) -> None:
        assert pipeline.detect_source_type(Path("firewall_traffic.csv")) == LogSource.FIREWALL

    def test_detects_auth(self, pipeline: IngestionPipeline) -> None:
        assert pipeline.detect_source_type(Path("auth.log")) == LogSource.AUTH

    def test_detects_syslog(self, pipeline: IngestionPipeline) -> None:
        assert pipeline.detect_source_type(Path("syslog.log")) == LogSource.SYSLOG

    def test_returns_none_for_unknown(self, pipeline: IngestionPipeline) -> None:
        assert pipeline.detect_source_type(Path("random_file.dat")) is None


class TestFirewallIngestion:
    """Test firewall log ingestion end-to-end."""

    def test_ingest_firewall_csv(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        stats = pipeline.ingest_file(
            sample_dir / "firewall_traffic.csv",
            source_type=LogSource.FIREWALL,
            show_progress=False,
        )
        assert stats["events_ingested"] > 0
        assert stats["errors"] == 0

    def test_firewall_events_stored(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        pipeline.ingest_file(
            sample_dir / "firewall_traffic.csv",
            source_type=LogSource.FIREWALL,
            show_progress=False,
        )
        assert pipeline.store.count_events() > 0


class TestAuthIngestion:
    """Test authentication log ingestion."""

    def test_ingest_auth_log(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        stats = pipeline.ingest_file(
            sample_dir / "auth.log",
            source_type=LogSource.AUTH,
            show_progress=False,
        )
        assert stats["events_ingested"] > 0

    def test_brute_force_detected(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        """Verify that the brute force burst in synthetic data is parsed."""
        pipeline.ingest_file(
            sample_dir / "auth.log",
            source_type=LogSource.AUTH,
            show_progress=False,
        )
        categories = pipeline.store.count_by_attack_category()
        assert "brute_force" in categories
        assert categories["brute_force"] >= 10  # We injected 50


class TestCICIDSIngestion:
    """Test CICIDS-format CSV ingestion."""

    def test_ingest_cicids_sample(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        stats = pipeline.ingest_file(
            sample_dir / "cicids_sample.csv",
            source_type=LogSource.CICIDS,
            show_progress=False,
        )
        assert stats["events_ingested"] > 0

    def test_severity_distribution(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        pipeline.ingest_file(
            sample_dir / "cicids_sample.csv",
            source_type=LogSource.CICIDS,
            show_progress=False,
        )
        severities = pipeline.store.count_by_severity()
        assert "benign" in severities  # Majority should be benign


class TestSyslogIngestion:
    """Test syslog ingestion."""

    def test_ingest_syslog(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        stats = pipeline.ingest_file(
            sample_dir / "syslog.log",
            source_type=LogSource.SYSLOG,
            show_progress=False,
        )
        assert stats["events_ingested"] > 0


class TestDirectoryIngestion:
    """Test ingesting an entire directory of mixed log types."""

    def test_ingest_directory(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        results = pipeline.ingest_directory(sample_dir)
        assert len(results) == 4  # 4 sample files
        total_events = sum(r["events_ingested"] for r in results)
        assert total_events > 300

    def test_store_summary(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        pipeline.ingest_directory(sample_dir)
        summary = pipeline.get_store_summary()
        assert summary["total_events"] > 0
        assert len(summary["by_severity"]) > 0
        assert len(summary["by_attack_category"]) > 0


class TestQueryCapabilities:
    """Test the storage query layer."""

    def test_top_source_ips(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        pipeline.ingest_directory(sample_dir)
        top_ips = pipeline.store.get_top_source_ips(limit=5)
        assert len(top_ips) > 0
        assert "src_ip" in top_ips[0]
        assert "count" in top_ips[0]

    def test_ingestion_history(self, pipeline: IngestionPipeline, sample_dir: Path) -> None:
        pipeline.ingest_directory(sample_dir)
        history = pipeline.store.get_ingestion_history()
        assert len(history) == 4
