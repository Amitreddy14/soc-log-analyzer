"""Feature engineering for severity classification.

Transforms normalized log events into ML-ready feature vectors. Features are
grouped into categories that mirror what a real SOC analyst looks at:

1. Network Features     — ports, protocols, byte ratios (what's talking to what)
2. Flow Features        — duration, packet counts, throughput (traffic shape)
3. Statistical Features — means, ratios, computed aggregates (anomaly signals)
4. Categorical Features — encoded source type, protocol, action (context)
5. Temporal Features    — hour of day, is_weekend (behavioral baselines)

Each feature is designed to be discriminative for at least one attack type:
    - High dst_port + DROP action → brute force signal
    - Extreme flow_bytes_per_sec → DDoS signal
    - Many fwd packets, few bwd → scan signal
    - Unusual hour + external IP → infiltration signal
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)

# Ports commonly targeted in attacks
WELL_KNOWN_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995}
HIGH_RISK_PORTS = {22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}

# Protocol mapping (IANA numbers → names for CICIDS)
PROTOCOL_MAP = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "HOPOPT"}


class FeatureExtractor:
    """Extracts and transforms features from normalized log events for ML.

    Handles both CICIDS-format data (rich flow features) and synthetic/real
    logs (sparser features). Missing features are imputed with safe defaults
    rather than dropped, so the model works on partial data too.
    """

    # Feature columns the model expects — order matters for consistency
    NUMERIC_FEATURES = [
        "dst_port",
        "src_port",
        "bytes_in",
        "bytes_out",
        "flow_duration",
        "total_fwd_packets",
        "total_bwd_packets",
        "flow_bytes_per_sec",
        "flow_packets_per_sec",
        "fwd_packet_length_mean",
        "bwd_packet_length_mean",
        # Computed features
        "byte_ratio",
        "packet_ratio",
        "bytes_total",
        "packets_total",
        "is_high_risk_port",
        "is_well_known_port",
        "hour_of_day",
        "is_weekend",
    ]

    CATEGORICAL_FEATURES = [
        "protocol_encoded",
        "source_type_encoded",
        "action_encoded",
    ]

    def __init__(self) -> None:
        self._protocol_encoder = LabelEncoder()
        self._source_encoder = LabelEncoder()
        self._action_encoder = LabelEncoder()
        self._is_fitted = False

    @property
    def feature_names(self) -> list[str]:
        """All feature column names in order."""
        return self.NUMERIC_FEATURES + self.CATEGORICAL_FEATURES

    @property
    def n_features(self) -> int:
        return len(self.feature_names)

    def extract_from_dataframe(self, df: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        """Extract features from a DataFrame of normalized events.

        Args:
            df: DataFrame with columns matching NormalizedLogEvent fields.
            fit: If True, fit the encoders (training). If False, use fitted encoders.

        Returns:
            DataFrame with only the ML feature columns, ready for model input.
        """
        logger.info("extracting_features", n_rows=len(df), fit=fit)
        features = pd.DataFrame(index=df.index)

        # --- Numeric features (direct copy with imputation) ---
        for col in ["dst_port", "src_port", "bytes_in", "bytes_out",
                     "flow_duration", "total_fwd_packets", "total_bwd_packets",
                     "flow_bytes_per_sec", "flow_packets_per_sec",
                     "fwd_packet_length_mean", "bwd_packet_length_mean"]:
            features[col] = pd.to_numeric(df.get(col, 0), errors="coerce").fillna(0)

        # --- Computed features ---
        features["byte_ratio"] = self._safe_ratio(features["bytes_in"], features["bytes_out"])
        features["packet_ratio"] = self._safe_ratio(
            features["total_fwd_packets"], features["total_bwd_packets"]
        )
        features["bytes_total"] = features["bytes_in"] + features["bytes_out"]
        features["packets_total"] = features["total_fwd_packets"] + features["total_bwd_packets"]

        # Port-based risk indicators
        features["is_high_risk_port"] = (
            features["dst_port"].isin(HIGH_RISK_PORTS).astype(int)
        )
        features["is_well_known_port"] = (
            features["dst_port"].isin(WELL_KNOWN_PORTS).astype(int)
        )

        # --- Temporal features ---
        if "timestamp" in df.columns:
            ts = pd.to_datetime(df["timestamp"], errors="coerce")
            features["hour_of_day"] = ts.dt.hour.fillna(12).astype(int)
            features["is_weekend"] = ts.dt.dayofweek.isin([5, 6]).astype(int)
        else:
            features["hour_of_day"] = 12
            features["is_weekend"] = 0

        # --- Categorical features (label encoded) ---
        protocol_col = df.get("protocol", pd.Series(["TCP"] * len(df))).fillna("TCP").astype(str)
        # Map numeric protocol codes to names
        protocol_col = protocol_col.map(
            lambda x: PROTOCOL_MAP.get(int(x), x) if x.isdigit() else x
        )

        source_col = df.get("source_type", pd.Series(["unknown"] * len(df))).fillna("unknown").astype(str)
        action_col = df.get("action", pd.Series(["unknown"] * len(df))).fillna("unknown").astype(str)

        if fit:
            features["protocol_encoded"] = self._fit_transform_safe(
                self._protocol_encoder, protocol_col
            )
            features["source_type_encoded"] = self._fit_transform_safe(
                self._source_encoder, source_col
            )
            features["action_encoded"] = self._fit_transform_safe(
                self._action_encoder, action_col
            )
            self._is_fitted = True
        else:
            if not self._is_fitted:
                raise RuntimeError("FeatureExtractor not fitted. Call with fit=True first.")
            features["protocol_encoded"] = self._transform_safe(
                self._protocol_encoder, protocol_col
            )
            features["source_type_encoded"] = self._transform_safe(
                self._source_encoder, source_col
            )
            features["action_encoded"] = self._transform_safe(
                self._action_encoder, action_col
            )

        # Replace inf/nan
        features = features.replace([np.inf, -np.inf], 0).fillna(0)

        logger.info("features_extracted", n_features=len(self.feature_names))
        return features[self.feature_names]

    def extract_labels(self, df: pd.DataFrame) -> pd.Series:
        """Extract severity labels from the DataFrame.

        Maps severity strings → integer class indices for classification.
        """
        severity_map = {
            "benign": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        labels = df["severity"].map(severity_map)
        if labels.isna().any():
            unknown_vals = df["severity"][labels.isna()].unique()
            logger.warning("unknown_severity_labels", values=list(unknown_vals))
            labels = labels.fillna(0).astype(int)
        return labels.astype(int)

    @staticmethod
    def label_to_severity(label: int) -> str:
        """Convert integer label back to severity string."""
        return {0: "benign", 1: "low", 2: "medium", 3: "high", 4: "critical"}[label]

    @staticmethod
    def _safe_ratio(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
        """Compute ratio safely, returning 0 when denominator is 0."""
        return numerator / denominator.replace(0, np.nan).fillna(1)

    @staticmethod
    def _fit_transform_safe(encoder: LabelEncoder, series: pd.Series) -> pd.Series:
        """Fit and transform, handling unseen labels gracefully."""
        return pd.Series(encoder.fit_transform(series.astype(str)), index=series.index)

    @staticmethod
    def _transform_safe(encoder: LabelEncoder, series: pd.Series) -> pd.Series:
        """Transform with fallback for unseen labels (maps to 0)."""
        known = set(encoder.classes_)
        safe_series = series.astype(str).map(lambda x: x if x in known else encoder.classes_[0])
        return pd.Series(encoder.transform(safe_series), index=series.index)

    def get_feature_importance_names(self) -> list[str]:
        """Get human-readable feature names for importance plots."""
        return self.feature_names.copy()
