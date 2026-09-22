"""Centralized configuration loaded from environment / .env file."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class DatabaseSettings(BaseSettings):
    path: str = Field(
        default=str(PROJECT_ROOT / "data" / "soc_analyzer.duckdb"),
        alias="DATABASE_PATH",
    )


class IngestionSettings(BaseSettings):
    batch_size: int = Field(default=5000, alias="BATCH_SIZE")
    max_workers: int = Field(default=4, alias="MAX_WORKERS")


class LoggingSettings(BaseSettings):
    level: str = Field(default="INFO", alias="LOG_LEVEL")
    format: str = Field(default="json", alias="LOG_FORMAT")


class Settings(BaseSettings):
    """Top-level application settings."""

    db: DatabaseSettings = DatabaseSettings()
    ingestion: IngestionSettings = IngestionSettings()
    logging: LoggingSettings = LoggingSettings()

    # Directories
    project_root: Path = PROJECT_ROOT
    data_dir: Path = PROJECT_ROOT / "data"
    raw_data_dir: Path = PROJECT_ROOT / "data" / "raw"
    sample_data_dir: Path = PROJECT_ROOT / "data" / "samples"

    def ensure_dirs(self) -> None:
        """Create required directories if they don't exist."""
        for d in [self.data_dir, self.raw_data_dir, self.sample_data_dir]:
            d.mkdir(parents=True, exist_ok=True)


settings = Settings()
