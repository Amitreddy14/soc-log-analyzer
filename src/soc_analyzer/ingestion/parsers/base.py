"""Abstract base parser — defines the contract every log source must implement.

Design Rationale:
    Every SOC ingests logs from 10+ different sources, each with its own format.
    The parser abstraction ensures we can add new sources (AWS CloudTrail,
    Palo Alto PAN-OS, CrowdStrike Falcon, etc.) without touching the pipeline.

    Each parser is responsible for:
    1. Reading raw data from its source format
    2. Yielding RawLogEvent objects (preserving original data)
    3. Normalizing each raw event into a NormalizedLogEvent (unified CEF schema)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from soc_analyzer.models.schemas import (
    LogSource,
    NormalizedLogEvent,
    RawLogEvent,
)
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)


class BaseParser(ABC):
    """Abstract base class for all log parsers."""

    source_type: LogSource

    def __init__(self) -> None:
        self._parsed_count = 0
        self._error_count = 0

    @abstractmethod
    def parse_file(self, filepath: Path) -> Iterator[RawLogEvent]:
        """Parse a file and yield raw log events.

        Args:
            filepath: Path to the log file.

        Yields:
            RawLogEvent objects with original data preserved.
        """
        ...

    @abstractmethod
    def normalize(self, raw_event: RawLogEvent) -> NormalizedLogEvent:
        """Normalize a raw event into the unified CEF schema.

        Args:
            raw_event: A raw log event from parse_file.

        Returns:
            NormalizedLogEvent in unified CEF-aligned format.
        """
        ...

    def parse_and_normalize(self, filepath: Path) -> Iterator[NormalizedLogEvent]:
        """Full pipeline: parse → normalize. Skips malformed records with logging.

        Args:
            filepath: Path to the log file.

        Yields:
            NormalizedLogEvent objects ready for storage.
        """
        for raw_event in self.parse_file(filepath):
            try:
                normalized = self.normalize(raw_event)
                self._parsed_count += 1
                yield normalized
            except Exception as e:
                self._error_count += 1
                logger.warning(
                    "normalization_failed",
                    event_id=raw_event.id,
                    source=self.source_type.value,
                    error=str(e),
                )

    @property
    def stats(self) -> dict[str, Any]:
        """Return parsing statistics."""
        total = self._parsed_count + self._error_count
        return {
            "source": self.source_type.value,
            "total_processed": total,
            "successful": self._parsed_count,
            "errors": self._error_count,
            "error_rate": f"{(self._error_count / total * 100):.2f}%" if total > 0 else "0%",
        }
