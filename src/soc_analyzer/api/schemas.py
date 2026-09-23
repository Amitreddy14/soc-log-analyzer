"""API response schemas — Pydantic models for REST endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class StatsResponse(BaseModel):
    total_events: int
    by_severity: dict[str, int]
    by_attack_category: dict[str, int]
    top_source_ips: list[dict[str, Any]]


class IngestionResponse(BaseModel):
    file: str
    source_type: str
    events_ingested: int
    errors: int
    duration_sec: float
    events_per_sec: int


class IncidentResponse(BaseModel):
    id: str
    title: str
    severity: str
    event_count: int
    source_ips: list[str]
    destination_ips: list[str]
    target_ports: list[int]
    attack_categories: list[str]
    attack_stages: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    duration_seconds: float
    events_per_minute: float
    confidence: float
    correlation_rule: str


class ReportResponse(BaseModel):
    incident_id: str
    severity: str
    title: str
    generator: str
    executive_summary: str
    timeline_narrative: str
    impact_assessment: str
    technical_details: str
    iocs: list[dict[str, str]]
    response_actions: list[dict[str, Any]]
    mitre_techniques: list[str]
    attack_stages: list[str]
    affected_assets: list[str]
    markdown: str  # Pre-rendered Markdown


class PipelineResponse(BaseModel):
    ingestion: IngestionResponse | None = None
    stats: StatsResponse
    incidents: list[IncidentResponse]
    reports: list[ReportResponse]


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str
    database: str
    events_count: int
    ollama_available: bool
    ollama_model: str | None = None
