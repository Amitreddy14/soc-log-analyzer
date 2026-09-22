"""Parser for the CICIDS-2017 dataset.

The Canadian Institute for Cybersecurity Intrusion Detection System dataset
contains labeled network flows with 78+ features extracted using CICFlowMeter.

Attack types in the dataset:
    - BENIGN (normal traffic)
    - DDoS, DoS Hulk, DoS GoldenEye, DoS Slowloris, DoS Slowhttptest
    - FTP-Patator, SSH-Patator (brute force)
    - PortScan
    - Bot (botnet)
    - Infiltration
    - Web Attack — Brute Force, XSS, SQL Injection
    - Heartbleed

The dataset files are CSVs with whitespace in column headers (a known quirk).
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pandas as pd

from soc_analyzer.ingestion.parsers.base import BaseParser
from soc_analyzer.models.schemas import (
    AttackCategory,
    LogSource,
    NormalizedLogEvent,
    RawLogEvent,
    SeverityLevel,
)
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)

# Map CICIDS labels → our AttackCategory enum
LABEL_MAP: dict[str, AttackCategory] = {
    "BENIGN": AttackCategory.BENIGN,
    "DDoS": AttackCategory.DDOS,
    "DoS Hulk": AttackCategory.DOS,
    "DoS GoldenEye": AttackCategory.DOS,
    "DoS slowloris": AttackCategory.DOS,
    "DoS Slowhttptest": AttackCategory.DOS,
    "FTP-Patator": AttackCategory.BRUTE_FORCE,
    "SSH-Patator": AttackCategory.BRUTE_FORCE,
    "PortScan": AttackCategory.PORT_SCAN,
    "Bot": AttackCategory.BOTNET,
    "Infiltration": AttackCategory.INFILTRATION,
    "Web Attack \x96 Brute Force": AttackCategory.WEB_ATTACK_BRUTEFORCE,
    "Web Attack \x96 XSS": AttackCategory.WEB_ATTACK_XSS,
    "Web Attack \x96 Sql Injection": AttackCategory.WEB_ATTACK_SQL,
    "Heartbleed": AttackCategory.HEARTBLEED,
    # Alternate label formats found in some versions
    "Web Attack Brute Force": AttackCategory.WEB_ATTACK_BRUTEFORCE,
    "Web Attack XSS": AttackCategory.WEB_ATTACK_XSS,
    "Web Attack Sql Injection": AttackCategory.WEB_ATTACK_SQL,
}

# Map attack categories → severity for ground-truth labeling
CATEGORY_SEVERITY: dict[AttackCategory, SeverityLevel] = {
    AttackCategory.BENIGN: SeverityLevel.BENIGN,
    AttackCategory.DOS: SeverityLevel.HIGH,
    AttackCategory.DDOS: SeverityLevel.CRITICAL,
    AttackCategory.BRUTE_FORCE: SeverityLevel.HIGH,
    AttackCategory.PORT_SCAN: SeverityLevel.MEDIUM,
    AttackCategory.BOTNET: SeverityLevel.CRITICAL,
    AttackCategory.INFILTRATION: SeverityLevel.CRITICAL,
    AttackCategory.WEB_ATTACK_XSS: SeverityLevel.HIGH,
    AttackCategory.WEB_ATTACK_SQL: SeverityLevel.CRITICAL,
    AttackCategory.WEB_ATTACK_BRUTEFORCE: SeverityLevel.MEDIUM,
    AttackCategory.HEARTBLEED: SeverityLevel.CRITICAL,
    AttackCategory.UNKNOWN: SeverityLevel.MEDIUM,
}


class CICIDSParser(BaseParser):
    """Parser for CICIDS-2017 CSV files."""

    source_type = LogSource.CICIDS

    def __init__(self, chunk_size: int = 10_000) -> None:
        super().__init__()
        self.chunk_size = chunk_size

    def _clean_columns(self, columns: list[str]) -> list[str]:
        """Strip whitespace from CICIDS column names (known dataset quirk)."""
        return [col.strip() for col in columns]

    def _classify_label(self, label: str) -> AttackCategory:
        """Map a CICIDS label string to our attack category enum."""
        label = label.strip()
        return LABEL_MAP.get(label, AttackCategory.UNKNOWN)

    def parse_file(self, filepath: Path) -> Iterator[RawLogEvent]:
        """Parse CICIDS CSV in chunks for memory efficiency.

        The full dataset is ~700MB across multiple files, so we stream
        it in chunks rather than loading it all into memory.
        """
        logger.info("parsing_cicids", file=str(filepath))

        for chunk in pd.read_csv(
            filepath,
            encoding="utf-8",
            encoding_errors="replace",
            low_memory=False,
            chunksize=self.chunk_size,
            na_values=["Infinity", "NaN", "inf", "-inf"],
        ):
            chunk.columns = self._clean_columns(list(chunk.columns))
            chunk = chunk.dropna(subset=["Label"])  # Drop rows without labels

            for _, row in chunk.iterrows():
                row_dict = row.to_dict()

                # Parse timestamp — CICIDS uses space-separated format
                timestamp_str = str(row_dict.get("Timestamp", ""))
                try:
                    timestamp = self._parse_cicids_timestamp(timestamp_str)
                except (ValueError, TypeError):
                    timestamp = datetime.now()

                yield RawLogEvent(
                    timestamp=timestamp,
                    source=LogSource.CICIDS,
                    raw_data=row_dict,
                    raw_text=None,
                )

    def _parse_cicids_timestamp(self, ts: str) -> datetime:
        """Parse CICIDS timestamp which uses DD/MM/YYYY HH:MM format."""
        for fmt in [
            "%d/%m/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M",
            "%Y-%m-%d %H:%M:%S",
        ]:
            try:
                return datetime.strptime(ts.strip(), fmt)
            except ValueError:
                continue
        raise ValueError(f"Cannot parse CICIDS timestamp: {ts}")

    def normalize(self, raw_event: RawLogEvent) -> NormalizedLogEvent:
        """Normalize a CICIDS row into the unified CEF schema."""
        data = raw_event.raw_data

        label = str(data.get("Label", "BENIGN")).strip()
        attack_cat = self._classify_label(label)
        severity = CATEGORY_SEVERITY.get(attack_cat, SeverityLevel.MEDIUM)

        # Safe numeric extraction
        def safe_float(key: str) -> float | None:
            val = data.get(key)
            try:
                v = float(val)
                return v if v == v and v != float("inf") and v != float("-inf") else None
            except (ValueError, TypeError):
                return None

        def safe_int(key: str) -> int | None:
            val = data.get(key)
            try:
                return int(float(val))
            except (ValueError, TypeError):
                return None

        return NormalizedLogEvent(
            raw_event_id=raw_event.id,
            timestamp=raw_event.timestamp,
            device_vendor="CIC",
            device_product="FlowMeter",
            signature_id=f"CICIDS-{attack_cat.value}",
            event_name=label,
            severity=severity,
            # Network fields
            src_ip=str(data.get("Source IP", data.get("Src IP", ""))),
            src_port=safe_int("Source Port") or safe_int("Src Port"),
            dst_ip=str(data.get("Destination IP", data.get("Dst IP", ""))),
            dst_port=safe_int("Destination Port") or safe_int("Dst Port"),
            protocol=str(data.get("Protocol", "")),
            bytes_in=safe_int("Total Length of Fwd Packets") or safe_int("TotalFwd Packets"),
            bytes_out=safe_int("Total Length of Bwd Packets") or safe_int("Total Backward Packets"),
            # Action
            action="alert" if attack_cat != AttackCategory.BENIGN else "allow",
            outcome="attack" if attack_cat != AttackCategory.BENIGN else "normal",
            # Source
            source_type=LogSource.CICIDS,
            # Classification (ground truth from dataset)
            attack_category=attack_cat,
            # Flow features for ML
            flow_duration=safe_float("Flow Duration"),
            total_fwd_packets=safe_int("Total Fwd Packets"),
            total_bwd_packets=safe_int("Total Backward Packets") or safe_int("Total Bwd packets"),
            flow_bytes_per_sec=safe_float("Flow Bytes/s"),
            flow_packets_per_sec=safe_float("Flow Packets/s"),
            fwd_packet_length_mean=safe_float("Fwd Packet Length Mean"),
            bwd_packet_length_mean=safe_float("Bwd Packet Length Mean"),
        )
