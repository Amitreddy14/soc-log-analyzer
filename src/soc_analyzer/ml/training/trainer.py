"""Model training pipeline for severity classification.

Supports two model tiers:
    1. Random Forest (baseline) — fast to train, interpretable, solid accuracy
    2. Gradient Boosted Trees (production) — higher accuracy, handles imbalance better

The trainer handles the full lifecycle:
    - Train/validation/test split with stratification
    - Class imbalance handling via SMOTE or class weights
    - Hyperparameter tuning via cross-validation
    - Model serialization (joblib) with metadata
    - Training run logging for reproducibility

Design choice: We use traditional ML (not deep learning) because:
    - Tabular data with 22 features → tree models dominate neural nets here
    - Interpretability matters in security (analysts need to trust the model)
    - Training on CPU in seconds, not hours
    - Feature importance directly maps to SOC analyst intuition
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.model_selection import (
    GridSearchCV,
    StratifiedKFold,
    train_test_split,
)
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from soc_analyzer.ml.features import FeatureExtractor
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)

SEVERITY_NAMES = ["benign", "low", "medium", "high", "critical"]

# Class weights to handle imbalance (attacks are rare vs benign traffic)
# These approximate real-world SOC data distributions
SEVERITY_WEIGHTS = {
    0: 1.0,    # benign — most common, lowest weight
    1: 2.0,    # low
    2: 4.0,    # medium
    3: 8.0,    # high — rare but important
    4: 16.0,   # critical — rarest, highest weight
}


class ModelTrainer:
    """End-to-end model training, evaluation, and persistence.

    Usage:
        trainer = ModelTrainer()
        trainer.load_data_from_db(pipeline)           # or load_data_from_csv()
        metrics = trainer.train(model_type="gradient_boosting")
        trainer.save("models/severity_classifier_v1")
    """

    def __init__(self, feature_extractor: FeatureExtractor | None = None) -> None:
        self.feature_extractor = feature_extractor or FeatureExtractor()
        self.model: Any = None
        self.model_type: str = ""
        self.metrics: dict[str, Any] = {}
        self.training_metadata: dict[str, Any] = {}

        # Data splits
        self.X_train: pd.DataFrame | None = None
        self.X_val: pd.DataFrame | None = None
        self.X_test: pd.DataFrame | None = None
        self.y_train: pd.Series | None = None
        self.y_val: pd.Series | None = None
        self.y_test: pd.Series | None = None

    def load_data_from_db(
        self,
        db_path: str,
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_state: int = 42,
    ) -> dict[str, int]:
        """Load events from DuckDB, extract features, and split.

        Args:
            db_path: Path to the DuckDB database.
            test_size: Fraction held out for final test.
            val_size: Fraction of remaining used for validation.
            random_state: Seed for reproducibility.

        Returns:
            Dict with split sizes.
        """
        import duckdb

        logger.info("loading_data_from_db", db_path=db_path)
        conn = duckdb.connect(db_path, read_only=True)
        df = conn.execute("SELECT * FROM events").fetchdf()
        conn.close()

        logger.info("loaded_events", count=len(df))
        return self._prepare_splits(df, test_size, val_size, random_state)

    def load_data_from_csv(
        self,
        filepath: str | Path,
        test_size: float = 0.15,
        val_size: float = 0.15,
        random_state: int = 42,
    ) -> dict[str, int]:
        """Load events from a CSV file.

        Useful for loading the full CICIDS-2017 dataset directly.
        The CSV should have columns matching NormalizedLogEvent or CICIDS format.
        """
        logger.info("loading_data_from_csv", file=str(filepath))
        df = pd.read_csv(filepath, low_memory=False)

        # Handle CICIDS column names (strip whitespace)
        df.columns = [c.strip() for c in df.columns]

        # If it's raw CICIDS format, we need to map columns
        if "Label" in df.columns and "severity" not in df.columns:
            df = self._map_cicids_to_normalized(df)

        logger.info("loaded_events", count=len(df))
        return self._prepare_splits(df, test_size, val_size, random_state)

    def _map_cicids_to_normalized(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map raw CICIDS DataFrame columns to normalized schema names."""
        from soc_analyzer.ingestion.parsers.cicids import LABEL_MAP, CATEGORY_SEVERITY

        # Map labels to attack categories then to severities
        df["attack_category"] = df["Label"].str.strip().map(
            {k: v.value for k, v in LABEL_MAP.items()}
        ).fillna("unknown")

        df["severity"] = df["Label"].str.strip().map(
            lambda x: CATEGORY_SEVERITY.get(
                LABEL_MAP.get(x), __import__("soc_analyzer.models.schemas", fromlist=["SeverityLevel"]).SeverityLevel.MEDIUM
            ).value
        )

        # Map column names
        column_map = {
            "Source IP": "src_ip",
            "Src IP": "src_ip",
            "Source Port": "src_port",
            "Src Port": "src_port",
            "Destination IP": "dst_ip",
            "Dst IP": "dst_ip",
            "Destination Port": "dst_port",
            "Dst Port": "dst_port",
            "Protocol": "protocol",
            "Flow Duration": "flow_duration",
            "Total Fwd Packets": "total_fwd_packets",
            "Total Backward Packets": "total_bwd_packets",
            "Total Bwd packets": "total_bwd_packets",
            "Total Length of Fwd Packets": "bytes_in",
            "Total Length of Bwd Packets": "bytes_out",
            "Flow Bytes/s": "flow_bytes_per_sec",
            "Flow Packets/s": "flow_packets_per_sec",
            "Fwd Packet Length Mean": "fwd_packet_length_mean",
            "Bwd Packet Length Mean": "bwd_packet_length_mean",
            "Timestamp": "timestamp",
        }
        df = df.rename(columns={k: v for k, v in column_map.items() if k in df.columns})

        # Set defaults for missing columns
        if "source_type" not in df.columns:
            df["source_type"] = "cicids"
        if "action" not in df.columns:
            df["action"] = df["attack_category"].apply(
                lambda x: "alert" if x != "benign" else "allow"
            )

        return df

    def _prepare_splits(
        self,
        df: pd.DataFrame,
        test_size: float,
        val_size: float,
        random_state: int,
    ) -> dict[str, int]:
        """Extract features and create stratified train/val/test splits."""

        # Drop rows with missing severity
        df = df.dropna(subset=["severity"])

        # Remove any inf values from numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

        # Extract features and labels
        X = self.feature_extractor.extract_from_dataframe(df, fit=True)
        y = self.feature_extractor.extract_labels(df)

        # Stratified split: first split off test, then split remaining into train/val
        X_temp, self.X_test, y_temp, self.y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y,
        )

        relative_val_size = val_size / (1 - test_size)
        self.X_train, self.X_val, self.y_train, self.y_val = train_test_split(
            X_temp, y_temp, test_size=relative_val_size,
            random_state=random_state, stratify=y_temp,
        )

        split_info = {
            "total": len(df),
            "train": len(self.X_train),
            "validation": len(self.X_val),
            "test": len(self.X_test),
            "n_classes": len(y.unique()),
            "class_distribution": y.value_counts().to_dict(),
        }

        logger.info("data_splits_ready", **split_info)
        return split_info

    def train(
        self,
        model_type: str = "gradient_boosting",
        tune_hyperparams: bool = False,
    ) -> dict[str, Any]:
        """Train a severity classification model.

        Args:
            model_type: "random_forest" or "gradient_boosting"
            tune_hyperparams: Whether to run grid search CV (slower but better).

        Returns:
            Dictionary of evaluation metrics.
        """
        if self.X_train is None:
            raise RuntimeError("No data loaded. Call load_data_from_db() or load_data_from_csv() first.")

        self.model_type = model_type
        start_time = time.time()
        logger.info("training_started", model_type=model_type, tune=tune_hyperparams)

        if model_type == "random_forest":
            self.model = self._train_random_forest(tune_hyperparams)
        elif model_type == "gradient_boosting":
            self.model = self._train_gradient_boosting(tune_hyperparams)
        else:
            raise ValueError(f"Unknown model type: {model_type}. Use 'random_forest' or 'gradient_boosting'.")

        train_duration = time.time() - start_time

        # Evaluate on validation set
        self.metrics = self._evaluate(self.X_val, self.y_val, dataset_name="validation")

        # Also get test metrics (but don't use for decisions — held out)
        test_metrics = self._evaluate(self.X_test, self.y_test, dataset_name="test")

        self.training_metadata = {
            "model_type": model_type,
            "tuned": tune_hyperparams,
            "train_duration_sec": round(train_duration, 2),
            "train_size": len(self.X_train),
            "n_features": self.feature_extractor.n_features,
            "feature_names": self.feature_extractor.feature_names,
            "trained_at": datetime.now().isoformat(),
            "validation_metrics": self.metrics,
            "test_metrics": test_metrics,
        }

        logger.info(
            "training_complete",
            duration=f"{train_duration:.2f}s",
            val_f1_macro=self.metrics["f1_macro"],
            test_f1_macro=test_metrics["f1_macro"],
        )

        return self.metrics

    def _train_random_forest(self, tune: bool) -> RandomForestClassifier:
        """Train a Random Forest classifier."""
        if tune:
            param_grid = {
                "n_estimators": [100, 200, 300],
                "max_depth": [10, 20, 30, None],
                "min_samples_split": [2, 5, 10],
                "min_samples_leaf": [1, 2, 4],
            }
            base_model = RandomForestClassifier(
                class_weight=SEVERITY_WEIGHTS,
                random_state=42,
                n_jobs=-1,
            )
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            grid_search = GridSearchCV(
                base_model, param_grid, cv=cv,
                scoring="f1_macro", n_jobs=-1, verbose=1,
            )
            grid_search.fit(self.X_train, self.y_train)
            logger.info("best_rf_params", params=grid_search.best_params_)
            return grid_search.best_estimator_
        else:
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                class_weight=SEVERITY_WEIGHTS,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(self.X_train, self.y_train)
            return model

    def _train_gradient_boosting(self, tune: bool) -> GradientBoostingClassifier:
        """Train a Gradient Boosting classifier.

        GBT handles class imbalance better than RF for our use case because
        it builds trees sequentially, focusing on misclassified samples.
        """
        # Compute sample weights from class weights
        sample_weights = self.y_train.map(SEVERITY_WEIGHTS).values

        if tune:
            param_grid = {
                "n_estimators": [100, 200, 300],
                "max_depth": [3, 5, 7],
                "learning_rate": [0.01, 0.05, 0.1],
                "subsample": [0.8, 1.0],
            }
            base_model = GradientBoostingClassifier(random_state=42)
            cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            grid_search = GridSearchCV(
                base_model, param_grid, cv=cv,
                scoring="f1_macro", n_jobs=-1, verbose=1,
            )
            grid_search.fit(self.X_train, self.y_train, sample_weight=sample_weights)
            logger.info("best_gbt_params", params=grid_search.best_params_)
            return grid_search.best_estimator_
        else:
            model = GradientBoostingClassifier(
                n_estimators=200,
                max_depth=5,
                learning_rate=0.1,
                subsample=0.8,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
            )
            model.fit(self.X_train, self.y_train, sample_weight=sample_weights)
            return model

    def _evaluate(
        self, X: pd.DataFrame, y: pd.Series, dataset_name: str = "validation"
    ) -> dict[str, Any]:
        """Evaluate model on a dataset and return comprehensive metrics."""
        y_pred = self.model.predict(X)
        y_proba = None
        if hasattr(self.model, "predict_proba"):
            y_proba = self.model.predict_proba(X)

        # Get the labels that actually appear in the data
        present_labels = sorted(set(y.unique()) | set(np.unique(y_pred)))
        present_names = [SEVERITY_NAMES[i] for i in present_labels if i < len(SEVERITY_NAMES)]

        metrics = {
            "dataset": dataset_name,
            "accuracy": round(accuracy_score(y, y_pred), 4),
            "f1_macro": round(f1_score(y, y_pred, average="macro", zero_division=0), 4),
            "f1_weighted": round(f1_score(y, y_pred, average="weighted", zero_division=0), 4),
            "precision_macro": round(precision_score(y, y_pred, average="macro", zero_division=0), 4),
            "recall_macro": round(recall_score(y, y_pred, average="macro", zero_division=0), 4),
            "confusion_matrix": confusion_matrix(y, y_pred, labels=present_labels).tolist(),
            "classification_report": classification_report(
                y, y_pred, labels=present_labels,
                target_names=present_names, zero_division=0, output_dict=True,
            ),
            "class_labels": present_names,
        }

        # Per-class confidence stats (if probabilities available)
        if y_proba is not None:
            max_proba = np.max(y_proba, axis=1)
            metrics["mean_confidence"] = round(float(np.mean(max_proba)), 4)
            metrics["confidence_by_class"] = {}
            for label_idx in present_labels:
                mask = y == label_idx
                if mask.any():
                    cls_conf = float(np.mean(max_proba[mask]))
                    metrics["confidence_by_class"][SEVERITY_NAMES[label_idx]] = round(cls_conf, 4)

        logger.info(
            f"evaluation_{dataset_name}",
            accuracy=metrics["accuracy"],
            f1_macro=metrics["f1_macro"],
        )
        return metrics

    def get_feature_importance(self, top_n: int = 15) -> list[dict[str, Any]]:
        """Get top N most important features."""
        if self.model is None:
            raise RuntimeError("No model trained yet.")

        importances = self.model.feature_importances_
        names = self.feature_extractor.get_feature_importance_names()

        sorted_idx = np.argsort(importances)[::-1][:top_n]
        return [
            {"feature": names[i], "importance": round(float(importances[i]), 4)}
            for i in sorted_idx
        ]

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Predict severity for new events.

        Args:
            df: DataFrame of normalized events.

        Returns:
            Original DataFrame with predicted_severity and confidence columns added.
        """
        if self.model is None:
            raise RuntimeError("No model trained or loaded.")

        X = self.feature_extractor.extract_from_dataframe(df, fit=False)
        predictions = self.model.predict(X)

        result = df.copy()
        result["predicted_severity"] = [
            FeatureExtractor.label_to_severity(p) for p in predictions
        ]

        if hasattr(self.model, "predict_proba"):
            probas = self.model.predict_proba(X)
            result["confidence"] = np.max(probas, axis=1).round(4)
        else:
            result["confidence"] = 1.0

        return result

    def save(self, directory: str | Path) -> Path:
        """Save model, feature extractor, and metadata.

        Saves three files:
            - model.joblib — the trained classifier
            - feature_extractor.joblib — fitted encoders and config
            - metadata.json — training run info, metrics, feature names
        """
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)

        model_path = directory / "model.joblib"
        extractor_path = directory / "feature_extractor.joblib"
        metadata_path = directory / "metadata.json"

        joblib.dump(self.model, model_path)
        joblib.dump(self.feature_extractor, extractor_path)

        with open(metadata_path, "w") as f:
            json.dump(self.training_metadata, f, indent=2, default=str)

        logger.info("model_saved", directory=str(directory))
        return directory

    @classmethod
    def load(cls, directory: str | Path) -> "ModelTrainer":
        """Load a saved model, feature extractor, and metadata."""
        directory = Path(directory)

        trainer = cls()
        trainer.model = joblib.load(directory / "model.joblib")
        trainer.feature_extractor = joblib.load(directory / "feature_extractor.joblib")

        with open(directory / "metadata.json") as f:
            trainer.training_metadata = json.load(f)

        trainer.model_type = trainer.training_metadata.get("model_type", "unknown")
        trainer.metrics = trainer.training_metadata.get("validation_metrics", {})

        logger.info("model_loaded", directory=str(directory))
        return trainer
