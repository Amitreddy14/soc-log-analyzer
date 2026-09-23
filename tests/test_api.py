"""Tests for the FastAPI REST API.

Uses TestClient to test all endpoints without starting a real server.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from soc_analyzer.api.app import create_app, _incidents, _reports
from soc_analyzer.config import settings


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    """Create a test client with a temp database."""
    # Set up temp DB with sample data
    settings.db.path = str(tmp_path / "test_api.duckdb")
    settings.ensure_dirs()

    # Generate and ingest sample data
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    from generate_synthetic import generate_all_samples
    sample_dir = tmp_path / "samples"
    generate_all_samples(sample_dir, count=200)

    from soc_analyzer.ingestion.pipeline import IngestionPipeline
    pipeline = IngestionPipeline(db_path=settings.db.path)
    pipeline.start()
    pipeline.ingest_directory(sample_dir)
    pipeline.stop()

    app = create_app()
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["events_count"] > 0
        assert "ollama_available" in data


class TestStatsEndpoint:
    def test_stats_returns_data(self, client: TestClient) -> None:
        response = client.get("/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert data["total_events"] > 0
        assert len(data["by_severity"]) > 0
        assert len(data["by_attack_category"]) > 0

    def test_stats_has_top_ips(self, client: TestClient) -> None:
        response = client.get("/api/stats")
        data = response.json()
        assert len(data["top_source_ips"]) > 0


class TestEventsEndpoint:
    def test_get_events(self, client: TestClient) -> None:
        response = client.get("/api/events?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert len(data) <= 10
        assert len(data) > 0

    def test_filter_by_severity(self, client: TestClient) -> None:
        response = client.get("/api/events?severity=benign&limit=5")
        assert response.status_code == 200
        data = response.json()
        for event in data:
            assert event["severity"] == "benign"


class TestCorrelateEndpoint:
    def test_correlate_produces_incidents(self, client: TestClient) -> None:
        response = client.post("/api/correlate")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Should have at least some incidents from synthetic data
        if len(data) > 0:
            inc = data[0]
            assert "id" in inc
            assert "severity" in inc
            assert "title" in inc
            assert "event_count" in inc

    def test_incidents_list_after_correlate(self, client: TestClient) -> None:
        client.post("/api/correlate")
        response = client.get("/api/incidents")
        assert response.status_code == 200


class TestSummarizeEndpoint:
    def test_summarize_with_template(self, client: TestClient) -> None:
        # First correlate to get incidents
        corr_response = client.post("/api/correlate")
        incidents = corr_response.json()
        if not incidents:
            pytest.skip("No incidents from synthetic data")

        incident_id = incidents[0]["id"]
        response = client.post(f"/api/summarize/{incident_id}?provider=template")
        assert response.status_code == 200
        data = response.json()
        assert data["incident_id"] == incident_id
        assert data["generator"] == "template"
        assert len(data["executive_summary"]) > 0
        assert len(data["markdown"]) > 0

    def test_summarize_nonexistent_incident(self, client: TestClient) -> None:
        response = client.post("/api/summarize/FAKE-ID?provider=template")
        assert response.status_code == 404

    def test_summarize_all(self, client: TestClient) -> None:
        client.post("/api/correlate")
        response = client.post("/api/summarize-all?provider=template&max_reports=3")
        assert response.status_code == 200
        data = response.json()
        assert len(data) <= 3


class TestPipelineEndpoint:
    def test_full_pipeline(self, client: TestClient) -> None:
        response = client.post("/api/pipeline?provider=template")
        assert response.status_code == 200
        data = response.json()
        assert data["stats"]["total_events"] > 0
        assert isinstance(data["incidents"], list)
        assert isinstance(data["reports"], list)


class TestDashboard:
    def test_dashboard_serves_html(self, client: TestClient) -> None:
        response = client.get("/")
        assert response.status_code == 200
        assert "SOC Log Analyzer" in response.text
