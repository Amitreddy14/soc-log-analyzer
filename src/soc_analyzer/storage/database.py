"""DuckDB storage backend for normalized security events.

Why DuckDB over SQLite:
    - Columnar storage → 10-100x faster analytical queries on log data
    - Native Parquet/CSV import for bulk loading
    - OLAP optimized — perfect for "show me all critical events in the last hour"
    - Embedded (no server), but upgradeable to MotherDuck for cloud
    - SQL compatible → easy migration to Elasticsearch/ClickHouse later
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import duckdb

from soc_analyzer.models.schemas import NormalizedLogEvent, SeverityLevel, LogSource
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)

CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id                      VARCHAR PRIMARY KEY,
    raw_event_id            VARCHAR,
    timestamp               TIMESTAMP NOT NULL,
    device_vendor           VARCHAR,
    device_product          VARCHAR,
    signature_id            VARCHAR,
    event_name              VARCHAR,
    severity                VARCHAR NOT NULL,
    src_ip                  VARCHAR,
    src_port                INTEGER,
    dst_ip                  VARCHAR,
    dst_port                INTEGER,
    protocol                VARCHAR,
    bytes_in                BIGINT,
    bytes_out               BIGINT,
    action                  VARCHAR,
    outcome                 VARCHAR,
    source_type             VARCHAR NOT NULL,
    source_host             VARCHAR,
    attack_category         VARCHAR,
    predicted_severity      VARCHAR,
    confidence              DOUBLE,
    incident_id             VARCHAR,
    flow_duration           DOUBLE,
    total_fwd_packets       INTEGER,
    total_bwd_packets       INTEGER,
    flow_bytes_per_sec      DOUBLE,
    flow_packets_per_sec    DOUBLE,
    fwd_packet_length_mean  DOUBLE,
    bwd_packet_length_mean  DOUBLE,
    extra                   JSON,
    ingested_at             TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common SOC queries
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events (dst_ip);
CREATE INDEX IF NOT EXISTS idx_events_attack_category ON events (attack_category);
CREATE INDEX IF NOT EXISTS idx_events_incident_id ON events (incident_id);
"""

CREATE_INGESTION_LOG = """
CREATE SEQUENCE IF NOT EXISTS ingestion_seq START 1;

CREATE TABLE IF NOT EXISTS ingestion_log (
    id              INTEGER PRIMARY KEY DEFAULT nextval('ingestion_seq'),
    source_file     VARCHAR NOT NULL,
    source_type     VARCHAR NOT NULL,
    records_total   INTEGER,
    records_success INTEGER,
    records_failed  INTEGER,
    started_at      TIMESTAMP,
    completed_at    TIMESTAMP,
    duration_sec    DOUBLE,
    status          VARCHAR DEFAULT 'running'
);
"""


class EventStore:
    """DuckDB-backed event storage with batch insert and query support."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._conn: duckdb.DuckDBPyConnection | None = None

    def connect(self) -> None:
        """Open a connection and ensure schema exists."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = duckdb.connect(self.db_path)
        self._conn.execute(CREATE_INGESTION_LOG)
        self._conn.execute(CREATE_EVENTS_TABLE)
        logger.info("database_connected", path=self.db_path)

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> duckdb.DuckDBPyConnection:
        if self._conn is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self._conn

    @contextmanager
    def transaction(self) -> Iterator[duckdb.DuckDBPyConnection]:
        """Context manager for transactional operations."""
        self.conn.begin()
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def insert_events(self, events: list[NormalizedLogEvent]) -> int:
        """Batch insert normalized events. Returns count of inserted rows."""
        if not events:
            return 0

        rows = []
        for e in events:
            rows.append((
                e.id, e.raw_event_id, e.timestamp,
                e.device_vendor, e.device_product, e.signature_id,
                e.event_name, e.severity.value,
                e.src_ip, e.src_port, e.dst_ip, e.dst_port,
                e.protocol, e.bytes_in, e.bytes_out,
                e.action, e.outcome,
                e.source_type.value, e.source_host,
                e.attack_category.value if e.attack_category else None,
                e.predicted_severity.value if e.predicted_severity else None,
                e.confidence, e.incident_id,
                e.flow_duration, e.total_fwd_packets, e.total_bwd_packets,
                e.flow_bytes_per_sec, e.flow_packets_per_sec,
                e.fwd_packet_length_mean, e.bwd_packet_length_mean,
                json.dumps(e.extra, default=str) if e.extra else None,
            ))

        placeholders = ", ".join(["?"] * 31)
        self.conn.executemany(
            f"INSERT OR IGNORE INTO events VALUES ({placeholders}, CURRENT_TIMESTAMP)",
            rows,
        )
        logger.info("events_inserted", count=len(rows))
        return len(rows)

    def log_ingestion(
        self,
        source_file: str,
        source_type: str,
        total: int,
        success: int,
        failed: int,
        started: datetime,
        completed: datetime,
    ) -> None:
        """Record an ingestion run in the audit log."""
        duration = (completed - started).total_seconds()
        self.conn.execute(
            """INSERT INTO ingestion_log
               (source_file, source_type, records_total, records_success,
                records_failed, started_at, completed_at, duration_sec, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (source_file, source_type, total, success, failed,
             started, completed, duration, "completed"),
        )

    # --- Query Methods (used by later phases and the API) ---

    def count_events(self) -> int:
        """Total number of events in the store."""
        result = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return result[0] if result else 0

    def count_by_severity(self) -> dict[str, int]:
        """Event count grouped by severity."""
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity ORDER BY cnt DESC"
        ).fetchall()
        return {row[0]: row[1] for row in rows}

    def count_by_attack_category(self) -> dict[str, int]:
        """Event count grouped by attack category."""
        rows = self.conn.execute(
            "SELECT attack_category, COUNT(*) as cnt FROM events GROUP BY attack_category ORDER BY cnt DESC"
        ).fetchall()
        return {row[0]: row[1] for row in rows}

    def get_top_source_ips(self, limit: int = 10, severity: str | None = None) -> list[dict]:
        """Get top source IPs by event count, optionally filtered by severity."""
        query = "SELECT src_ip, COUNT(*) as cnt FROM events"
        params: list = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity)
        query += " GROUP BY src_ip ORDER BY cnt DESC LIMIT ?"
        params.append(limit)
        rows = self.conn.execute(query, params).fetchall()
        return [{"src_ip": r[0], "count": r[1]} for r in rows]

    def get_events_in_range(
        self,
        start: datetime,
        end: datetime,
        severity: str | None = None,
        limit: int = 1000,
    ) -> list[dict]:
        """Retrieve events within a time range."""
        query = "SELECT * FROM events WHERE timestamp BETWEEN ? AND ?"
        params: list = [start, end]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = self.conn.execute(query, params).fetchall()
        columns = [desc[0] for desc in self.conn.description]
        return [dict(zip(columns, row)) for row in rows]

    def get_ingestion_history(self, limit: int = 20) -> list[dict]:
        """Get recent ingestion runs."""
        rows = self.conn.execute(
            "SELECT * FROM ingestion_log ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        columns = [desc[0] for desc in self.conn.description]
        return [dict(zip(columns, row)) for row in rows]
