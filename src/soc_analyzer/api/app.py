"""FastAPI application — REST API for the SOC Log Analyzer.

Endpoints:
    GET  /health              — service health and Ollama status
    GET  /api/stats            — event store statistics
    GET  /api/events           — query events with filters
    POST /api/ingest           — ingest a log file
    GET  /api/incidents        — list correlated incidents
    POST /api/correlate        — run correlation on stored events
    POST /api/summarize/{id}   — generate report for one incident
    POST /api/pipeline         — full pipeline: ingest → correlate → summarize
    GET  /                     — serve the dashboard
"""

from __future__ import annotations

import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from soc_analyzer import __version__
from soc_analyzer.api.schemas import (
    HealthResponse,
    IncidentResponse,
    IngestionResponse,
    PipelineResponse,
    ReportResponse,
    StatsResponse,
)
from soc_analyzer.config import settings
from soc_analyzer.correlation import CorrelationEngine, Incident
from soc_analyzer.correlation.strategies import (
    AttackChainCorrelator,
    StatisticalCorrelator,
    TimeWindowCorrelator,
)
from soc_analyzer.ingestion.pipeline import IngestionPipeline
from soc_analyzer.models.schemas import (
    AttackCategory,
    LogSource,
    NormalizedLogEvent,
    SeverityLevel,
)
from soc_analyzer.storage.database import EventStore
from soc_analyzer.summarization import SummarizationEngine
from soc_analyzer.summarization.report import IncidentReport
from soc_analyzer.utils.logger import get_logger, setup_logging

logger = get_logger(__name__)

# In-memory state for incidents and reports (persisted per session)
_incidents: list[Incident] = []
_reports: list[IncidentReport] = []


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    setup_logging()

    app = FastAPI(
        title="SOC Log Analyzer API",
        description="LLM-powered security log triage, correlation, and summarization",
        version=__version__,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _register_routes(app)
    return app


def _get_store() -> EventStore:
    """Get a connected EventStore instance."""
    store = EventStore(settings.db.path)
    store.connect()
    return store


def _check_ollama(base_url: str = "http://localhost:11434") -> tuple[bool, str | None]:
    """Check if Ollama is running and get the default model."""
    try:
        import httpx
        resp = httpx.get(f"{base_url}/api/tags", timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            models = data.get("models", [])
            if models:
                return True, models[0].get("name", "llama3")
            return True, None
        return False, None
    except Exception:
        return False, None


def _load_events_from_db() -> list[NormalizedLogEvent]:
    """Load all events from the database as NormalizedLogEvent objects."""
    import duckdb
    conn = duckdb.connect(settings.db.path, read_only=True)
    df = conn.execute("SELECT * FROM events").fetchdf()
    conn.close()

    events: list[NormalizedLogEvent] = []
    for _, row in df.iterrows():
        try:
            events.append(NormalizedLogEvent(
                id=str(row.get("id", "")),
                timestamp=row["timestamp"],
                severity=SeverityLevel(row["severity"]),
                source_type=LogSource(row["source_type"]),
                src_ip=row.get("src_ip"),
                src_port=int(row["src_port"]) if pd.notna(row.get("src_port")) else None,
                dst_ip=row.get("dst_ip"),
                dst_port=int(row["dst_port"]) if pd.notna(row.get("dst_port")) else None,
                protocol=row.get("protocol"),
                bytes_in=int(row["bytes_in"]) if pd.notna(row.get("bytes_in")) else None,
                bytes_out=int(row["bytes_out"]) if pd.notna(row.get("bytes_out")) else None,
                action=row.get("action"),
                event_name=row.get("event_name", ""),
                attack_category=AttackCategory(row["attack_category"]) if row.get("attack_category") else AttackCategory.UNKNOWN,
                flow_duration=float(row["flow_duration"]) if pd.notna(row.get("flow_duration")) else None,
                total_fwd_packets=int(row["total_fwd_packets"]) if pd.notna(row.get("total_fwd_packets")) else None,
                total_bwd_packets=int(row["total_bwd_packets"]) if pd.notna(row.get("total_bwd_packets")) else None,
                flow_bytes_per_sec=float(row["flow_bytes_per_sec"]) if pd.notna(row.get("flow_bytes_per_sec")) else None,
            ))
        except Exception:
            continue
    return events


def _incident_to_response(inc: Incident) -> IncidentResponse:
    """Convert an Incident to API response."""
    return IncidentResponse(
        id=inc.id,
        title=inc.title,
        severity=inc.severity.value,
        event_count=inc.event_count,
        source_ips=inc.source_ips,
        destination_ips=inc.destination_ips,
        target_ports=inc.target_ports,
        attack_categories=inc.attack_categories,
        attack_stages=inc.attack_stages,
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        duration_seconds=inc.duration_seconds,
        events_per_minute=inc.events_per_minute,
        confidence=inc.confidence,
        correlation_rule=inc.correlation_rule,
    )


def _report_to_response(report: IncidentReport) -> ReportResponse:
    """Convert an IncidentReport to API response."""
    return ReportResponse(
        incident_id=report.incident_id,
        severity=report.severity,
        title=report.title,
        generator=report.generator,
        executive_summary=report.executive_summary,
        timeline_narrative=report.timeline_narrative,
        impact_assessment=report.impact_assessment,
        technical_details=report.technical_details,
        iocs=[ioc.model_dump() for ioc in report.iocs],
        response_actions=[a.model_dump() for a in report.response_actions],
        mitre_techniques=report.mitre_techniques,
        attack_stages=report.attack_stages,
        affected_assets=report.affected_assets,
        markdown=report.to_markdown(),
    )


def _register_routes(app: FastAPI) -> None:
    """Register all API routes."""

    @app.get("/health", response_model=HealthResponse)
    async def health():
        """Health check — includes Ollama status."""
        store = _get_store()
        count = store.count_events()
        store.close()
        ollama_ok, ollama_model = _check_ollama()
        return HealthResponse(
            status="healthy",
            version=__version__,
            database=settings.db.path,
            events_count=count,
            ollama_available=ollama_ok,
            ollama_model=ollama_model,
        )

    @app.get("/api/stats", response_model=StatsResponse)
    async def get_stats():
        """Get event store statistics."""
        store = _get_store()
        try:
            return StatsResponse(
                total_events=store.count_events(),
                by_severity=store.count_by_severity(),
                by_attack_category=store.count_by_attack_category(),
                top_source_ips=store.get_top_source_ips(limit=10),
            )
        finally:
            store.close()

    @app.get("/api/events")
    async def get_events(
        severity: str | None = None,
        limit: int = Query(default=100, le=5000),
        offset: int = 0,
    ):
        """Query events with optional severity filter."""
        import duckdb
        conn = duckdb.connect(settings.db.path, read_only=True)
        query = "SELECT * FROM events"
        params: list = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        columns = [desc[0] for desc in conn.description]
        conn.close()
        return [dict(zip(columns, row)) for row in rows]

    @app.post("/api/ingest", response_model=IngestionResponse)
    async def ingest_file(file: UploadFile = File(...), source_type: str | None = None):
        """Ingest an uploaded log file."""
        # Save uploaded file to temp location
        suffix = Path(file.filename or "upload.log").suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            content = await file.read()
            tmp.write(content)
            tmp_path = tmp.name

        try:
            pipeline = IngestionPipeline()
            pipeline.start()
            src = LogSource(source_type) if source_type else None
            stats = pipeline.ingest_file(tmp_path, source_type=src, show_progress=False)
            pipeline.stop()
            return IngestionResponse(**stats)
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    @app.post("/api/correlate", response_model=list[IncidentResponse])
    async def correlate_events(
        window_seconds: int = 300,
        min_events: int = 3,
    ):
        """Run correlation on all stored events."""
        global _incidents
        events = _load_events_from_db()
        if not events:
            raise HTTPException(status_code=404, detail="No events in database. Ingest some first.")

        engine = CorrelationEngine(strategies=[
            TimeWindowCorrelator(window_seconds=window_seconds, min_events=min_events),
            AttackChainCorrelator(window_seconds=3600, min_stages=2),
            StatisticalCorrelator(eps=0.5, min_samples=5),
        ])
        _incidents = engine.correlate(events)
        return [_incident_to_response(inc) for inc in _incidents]

    @app.get("/api/incidents", response_model=list[IncidentResponse])
    async def list_incidents():
        """List current correlated incidents."""
        return [_incident_to_response(inc) for inc in _incidents]

    @app.post("/api/summarize/{incident_id}", response_model=ReportResponse)
    async def summarize_incident(
        incident_id: str,
        provider: str = "ollama",
        model: str | None = None,
    ):
        """Generate a report for a specific incident."""
        incident = next((i for i in _incidents if i.id == incident_id), None)
        if not incident:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

        engine = SummarizationEngine(provider=provider if provider != "template" else None, model=model)
        report = engine.summarize(incident)
        _reports.append(report)
        return _report_to_response(report)

    @app.post("/api/summarize-all", response_model=list[ReportResponse])
    async def summarize_all(
        provider: str = "ollama",
        model: str | None = None,
        max_reports: int | None = None,
    ):
        """Generate reports for all incidents."""
        global _reports
        if not _incidents:
            raise HTTPException(status_code=404, detail="No incidents. Run /api/correlate first.")

        engine = SummarizationEngine(provider=provider if provider != "template" else None, model=model)
        _reports = engine.summarize_all(_incidents, max_reports=max_reports)
        return [_report_to_response(r) for r in _reports]

    @app.get("/api/reports", response_model=list[ReportResponse])
    async def list_reports():
        """List generated reports."""
        return [_report_to_response(r) for r in _reports]

    @app.post("/api/pipeline", response_model=PipelineResponse)
    async def run_pipeline(
        provider: str = "template",
        model: str | None = None,
    ):
        """Run the full pipeline: load → correlate → summarize."""
        global _incidents, _reports

        events = _load_events_from_db()
        if not events:
            raise HTTPException(status_code=404, detail="No events in database.")

        # Correlate
        corr_engine = CorrelationEngine(strategies=[
            TimeWindowCorrelator(window_seconds=300, min_events=3),
            AttackChainCorrelator(window_seconds=3600, min_stages=2),
            StatisticalCorrelator(eps=0.5, min_samples=5),
        ])
        _incidents = corr_engine.correlate(events)

        # Stats
        store = _get_store()
        stats = StatsResponse(
            total_events=store.count_events(),
            by_severity=store.count_by_severity(),
            by_attack_category=store.count_by_attack_category(),
            top_source_ips=store.get_top_source_ips(limit=10),
        )
        store.close()

        # Summarize
        sum_engine = SummarizationEngine(
            provider=provider if provider != "template" else None,
            model=model,
        )
        _reports = sum_engine.summarize_all(_incidents, max_reports=10)

        return PipelineResponse(
            stats=stats,
            incidents=[_incident_to_response(i) for i in _incidents],
            reports=[_report_to_response(r) for r in _reports],
        )

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        """Serve the SOC dashboard."""
        dashboard_path = Path(__file__).parent / "dashboard.html"
        if dashboard_path.exists():
            return HTMLResponse(dashboard_path.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>Dashboard not found. Run from the project root.</h1>")
