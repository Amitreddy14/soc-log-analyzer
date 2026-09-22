"""Severity classifier — inference interface for the trained model.

This is the production-facing class that the pipeline and API use.
It loads a saved model and provides a clean predict() interface.

Usage:
    classifier = SeverityClassifier.from_saved("models/severity_v1")
    event.predicted_severity = classifier.classify(event)
    events = classifier.classify_batch(events)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from soc_analyzer.ml.training.trainer import ModelTrainer
from soc_analyzer.models.schemas import NormalizedLogEvent, SeverityLevel
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)


class SeverityClassifier:
    """Production inference wrapper for the severity classification model."""

    def __init__(self, trainer: ModelTrainer) -> None:
        self._trainer = trainer
        if trainer.model is None:
            raise RuntimeError("Trainer has no model loaded.")

    @classmethod
    def from_saved(cls, model_dir: str | Path) -> "SeverityClassifier":
        """Load a classifier from a saved model directory.

        Args:
            model_dir: Path containing model.joblib, feature_extractor.joblib, metadata.json

        Returns:
            Ready-to-use SeverityClassifier instance.
        """
        trainer = ModelTrainer.load(model_dir)
        return cls(trainer)

    def classify(self, event: NormalizedLogEvent) -> tuple[SeverityLevel, float]:
        """Classify a single event.

        Args:
            event: A normalized log event.

        Returns:
            Tuple of (predicted_severity, confidence_score).
        """
        df = pd.DataFrame([event.model_dump()])
        X = self._trainer.feature_extractor.extract_from_dataframe(df, fit=False)

        prediction = self._trainer.model.predict(X)[0]
        severity_str = self._trainer.feature_extractor.label_to_severity(prediction)
        severity = SeverityLevel(severity_str)

        confidence = 1.0
        if hasattr(self._trainer.model, "predict_proba"):
            probas = self._trainer.model.predict_proba(X)[0]
            confidence = float(np.max(probas))

        return severity, round(confidence, 4)

    def classify_batch(
        self, events: list[NormalizedLogEvent]
    ) -> list[NormalizedLogEvent]:
        """Classify a batch of events, updating each with predicted severity.

        Args:
            events: List of normalized log events.

        Returns:
            The same events with predicted_severity and confidence populated.
        """
        if not events:
            return events

        df = pd.DataFrame([e.model_dump() for e in events])
        X = self._trainer.feature_extractor.extract_from_dataframe(df, fit=False)

        predictions = self._trainer.model.predict(X)
        confidences = np.ones(len(predictions))
        if hasattr(self._trainer.model, "predict_proba"):
            probas = self._trainer.model.predict_proba(X)
            confidences = np.max(probas, axis=1)

        for event, pred, conf in zip(events, predictions, confidences):
            severity_str = self._trainer.feature_extractor.label_to_severity(pred)
            event.predicted_severity = SeverityLevel(severity_str)
            event.confidence = round(float(conf), 4)

        logger.info("batch_classified", count=len(events))
        return events

    @property
    def model_info(self) -> dict[str, Any]:
        """Return model metadata."""
        return {
            "model_type": self._trainer.model_type,
            "n_features": self._trainer.feature_extractor.n_features,
            "metrics": self._trainer.metrics,
        }
