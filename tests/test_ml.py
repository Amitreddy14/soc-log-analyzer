"""Tests for the ML severity classification pipeline.

Covers feature extraction, model training, evaluation, save/load, and inference.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from soc_analyzer.ml.features import FeatureExtractor
from soc_analyzer.ml.training import ModelTrainer
from soc_analyzer.ml.classifier import SeverityClassifier
from soc_analyzer.ml.evaluation import EvaluationReport
from soc_analyzer.models.schemas import LogSource, NormalizedLogEvent, SeverityLevel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from generate_synthetic import generate_sample_cicids


@pytest.fixture
def sample_cicids_csv(tmp_path: Path) -> Path:
    """Generate a sample CICIDS CSV."""
    return generate_sample_cicids(tmp_path, count=1000)


@pytest.fixture
def sample_dataframe() -> pd.DataFrame:
    """Create a sample DataFrame mimicking normalized events."""
    np.random.seed(42)
    n = 500
    severities = np.random.choice(
        ["benign", "low", "medium", "high", "critical"],
        size=n,
        p=[0.6, 0.1, 0.1, 0.1, 0.1],
    )
    return pd.DataFrame({
        "timestamp": pd.date_range("2024-01-01", periods=n, freq="min"),
        "src_ip": [f"192.168.1.{np.random.randint(1, 50)}" for _ in range(n)],
        "src_port": np.random.randint(1024, 65535, size=n),
        "dst_ip": [f"10.0.0.{np.random.randint(1, 20)}" for _ in range(n)],
        "dst_port": np.random.choice([22, 80, 443, 3306, 8080, 445, 3389], size=n),
        "protocol": np.random.choice(["TCP", "UDP"], size=n, p=[0.8, 0.2]),
        "bytes_in": np.random.randint(40, 100000, size=n),
        "bytes_out": np.random.randint(0, 80000, size=n),
        "flow_duration": np.random.randint(0, 120_000_000, size=n),
        "total_fwd_packets": np.random.randint(1, 500, size=n),
        "total_bwd_packets": np.random.randint(0, 300, size=n),
        "flow_bytes_per_sec": np.random.uniform(0, 1e7, size=n),
        "flow_packets_per_sec": np.random.uniform(0, 5000, size=n),
        "fwd_packet_length_mean": np.random.uniform(20, 1500, size=n),
        "bwd_packet_length_mean": np.random.uniform(0, 1500, size=n),
        "severity": severities,
        "source_type": "cicids",
        "action": np.where(severities != "benign", "alert", "allow"),
    })


class TestFeatureExtractor:
    """Test the feature engineering pipeline."""

    def test_extract_features_shape(self, sample_dataframe: pd.DataFrame) -> None:
        extractor = FeatureExtractor()
        features = extractor.extract_from_dataframe(sample_dataframe, fit=True)
        assert features.shape[0] == len(sample_dataframe)
        assert features.shape[1] == extractor.n_features

    def test_feature_names_consistent(self, sample_dataframe: pd.DataFrame) -> None:
        extractor = FeatureExtractor()
        features = extractor.extract_from_dataframe(sample_dataframe, fit=True)
        assert list(features.columns) == extractor.feature_names

    def test_no_nan_or_inf(self, sample_dataframe: pd.DataFrame) -> None:
        extractor = FeatureExtractor()
        features = extractor.extract_from_dataframe(sample_dataframe, fit=True)
        assert not features.isna().any().any()
        assert not np.isinf(features.values).any()

    def test_labels_extraction(self, sample_dataframe: pd.DataFrame) -> None:
        extractor = FeatureExtractor()
        labels = extractor.extract_labels(sample_dataframe)
        assert len(labels) == len(sample_dataframe)
        assert set(labels.unique()).issubset({0, 1, 2, 3, 4})

    def test_transform_without_fit_raises(self, sample_dataframe: pd.DataFrame) -> None:
        extractor = FeatureExtractor()
        with pytest.raises(RuntimeError, match="not fitted"):
            extractor.extract_from_dataframe(sample_dataframe, fit=False)

    def test_high_risk_port_detection(self, sample_dataframe: pd.DataFrame) -> None:
        extractor = FeatureExtractor()
        features = extractor.extract_from_dataframe(sample_dataframe, fit=True)
        # Port 445 and 3389 are high risk
        mask_445 = sample_dataframe["dst_port"] == 445
        assert features.loc[mask_445, "is_high_risk_port"].all()

    def test_temporal_features(self, sample_dataframe: pd.DataFrame) -> None:
        extractor = FeatureExtractor()
        features = extractor.extract_from_dataframe(sample_dataframe, fit=True)
        assert features["hour_of_day"].between(0, 23).all()
        assert features["is_weekend"].isin([0, 1]).all()


class TestModelTrainer:
    """Test model training pipeline."""

    def test_train_random_forest(self, sample_dataframe: pd.DataFrame) -> None:
        trainer = ModelTrainer()
        trainer._prepare_splits(sample_dataframe, 0.15, 0.15, 42)
        metrics = trainer.train(model_type="random_forest")
        assert metrics["accuracy"] > 0.3  # Better than random on 5 classes
        assert "f1_macro" in metrics
        assert "confusion_matrix" in metrics

    def test_train_gradient_boosting(self, sample_dataframe: pd.DataFrame) -> None:
        trainer = ModelTrainer()
        trainer._prepare_splits(sample_dataframe, 0.15, 0.15, 42)
        metrics = trainer.train(model_type="gradient_boosting")
        assert metrics["accuracy"] > 0.3
        assert "f1_macro" in metrics

    def test_feature_importance(self, sample_dataframe: pd.DataFrame) -> None:
        trainer = ModelTrainer()
        trainer._prepare_splits(sample_dataframe, 0.15, 0.15, 42)
        trainer.train(model_type="random_forest")
        importances = trainer.get_feature_importance(top_n=5)
        assert len(importances) == 5
        assert all("feature" in item and "importance" in item for item in importances)
        # Importances should be sorted descending
        imps = [item["importance"] for item in importances]
        assert imps == sorted(imps, reverse=True)

    def test_save_and_load(self, sample_dataframe: pd.DataFrame, tmp_path: Path) -> None:
        trainer = ModelTrainer()
        trainer._prepare_splits(sample_dataframe, 0.15, 0.15, 42)
        trainer.train(model_type="random_forest")

        # Save
        save_dir = tmp_path / "test_model"
        trainer.save(save_dir)
        assert (save_dir / "model.joblib").exists()
        assert (save_dir / "feature_extractor.joblib").exists()
        assert (save_dir / "metadata.json").exists()

        # Load
        loaded = ModelTrainer.load(save_dir)
        assert loaded.model is not None
        assert loaded.model_type == "random_forest"

    def test_predict_after_train(self, sample_dataframe: pd.DataFrame) -> None:
        trainer = ModelTrainer()
        trainer._prepare_splits(sample_dataframe, 0.15, 0.15, 42)
        trainer.train(model_type="random_forest")

        # Predict on new data
        new_data = sample_dataframe.head(10).copy()
        result = trainer.predict(new_data)
        assert "predicted_severity" in result.columns
        assert "confidence" in result.columns
        assert len(result) == 10

    def test_load_from_csv(self, sample_cicids_csv: Path) -> None:
        trainer = ModelTrainer()
        split_info = trainer.load_data_from_csv(sample_cicids_csv)
        assert split_info["total"] > 0
        assert split_info["train"] > 0

    def test_invalid_model_type_raises(self, sample_dataframe: pd.DataFrame) -> None:
        trainer = ModelTrainer()
        trainer._prepare_splits(sample_dataframe, 0.15, 0.15, 42)
        with pytest.raises(ValueError, match="Unknown model type"):
            trainer.train(model_type="neural_network")


class TestSeverityClassifier:
    """Test the inference wrapper."""

    @pytest.fixture
    def trained_classifier(self, sample_dataframe: pd.DataFrame, tmp_path: Path) -> SeverityClassifier:
        trainer = ModelTrainer()
        trainer._prepare_splits(sample_dataframe, 0.15, 0.15, 42)
        trainer.train(model_type="random_forest")
        save_dir = tmp_path / "clf_model"
        trainer.save(save_dir)
        return SeverityClassifier.from_saved(save_dir)

    def test_classify_single(self, trained_classifier: SeverityClassifier) -> None:
        from datetime import datetime
        event = NormalizedLogEvent(
            timestamp=datetime.now(),
            source_type=LogSource.FIREWALL,
            severity=SeverityLevel.BENIGN,
            dst_port=22,
            src_ip="91.240.118.172",
            protocol="TCP",
            action="deny",
        )
        severity, confidence = trained_classifier.classify(event)
        assert isinstance(severity, SeverityLevel)
        assert 0.0 <= confidence <= 1.0

    def test_classify_batch(self, trained_classifier: SeverityClassifier) -> None:
        from datetime import datetime
        events = [
            NormalizedLogEvent(
                timestamp=datetime.now(),
                source_type=LogSource.FIREWALL,
                severity=SeverityLevel.BENIGN,
                dst_port=port,
                protocol="TCP",
                action=action,
            )
            for port, action in [(80, "allow"), (22, "deny"), (3389, "deny"), (443, "allow")]
        ]
        classified = trained_classifier.classify_batch(events)
        assert len(classified) == 4
        assert all(e.predicted_severity is not None for e in classified)
        assert all(e.confidence is not None for e in classified)

    def test_model_info(self, trained_classifier: SeverityClassifier) -> None:
        info = trained_classifier.model_info
        assert "model_type" in info
        assert "n_features" in info
        assert "metrics" in info


class TestEvaluationReport:
    """Test report generation."""

    def test_save_report(self, sample_dataframe: pd.DataFrame, tmp_path: Path) -> None:
        trainer = ModelTrainer()
        trainer._prepare_splits(sample_dataframe, 0.15, 0.15, 42)
        trainer.train(model_type="random_forest")

        report = EvaluationReport(trainer)
        report_path = report.save_report(tmp_path / "reports")
        assert report_path.exists()
