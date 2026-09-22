"""Evaluation report generation for trained models.

Produces:
    - Classification report (precision/recall/F1 per class)
    - Confusion matrix visualization
    - Feature importance chart
    - Confidence distribution analysis
    - Summary statistics for quick assessment

All outputs saved to a report directory for documentation and GitHub README.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from soc_analyzer.ml.training.trainer import ModelTrainer, SEVERITY_NAMES
from soc_analyzer.utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


class EvaluationReport:
    """Generate and display evaluation reports for trained models."""

    def __init__(self, trainer: ModelTrainer) -> None:
        self.trainer = trainer

    def print_summary(self) -> None:
        """Print a rich summary of model performance to the console."""
        metrics = self.trainer.metrics
        if not metrics:
            console.print("[red]No metrics available. Train a model first.[/]")
            return

        # Header
        console.print(Panel(
            f"[bold cyan]{self.trainer.model_type.replace('_', ' ').title()}[/] "
            f"— {self.trainer.training_metadata.get('train_size', '?')} training samples, "
            f"{self.trainer.feature_extractor.n_features} features",
            title="Model Evaluation Report",
        ))

        # Overall metrics
        metrics_table = Table(title="Overall Metrics")
        metrics_table.add_column("Metric", style="bold")
        metrics_table.add_column("Score", justify="right")

        metrics_table.add_row("Accuracy", f"{metrics['accuracy']:.4f}")
        metrics_table.add_row("F1 (macro)", f"{metrics['f1_macro']:.4f}")
        metrics_table.add_row("F1 (weighted)", f"{metrics['f1_weighted']:.4f}")
        metrics_table.add_row("Precision (macro)", f"{metrics['precision_macro']:.4f}")
        metrics_table.add_row("Recall (macro)", f"{metrics['recall_macro']:.4f}")
        if "mean_confidence" in metrics:
            metrics_table.add_row("Mean Confidence", f"{metrics['mean_confidence']:.4f}")

        console.print(metrics_table)

        # Per-class metrics
        self._print_per_class_metrics(metrics)

        # Confusion matrix
        self._print_confusion_matrix(metrics)

        # Feature importance
        self._print_feature_importance()

    def _print_per_class_metrics(self, metrics: dict[str, Any]) -> None:
        """Print per-class precision/recall/F1 table."""
        report = metrics.get("classification_report", {})
        class_labels = metrics.get("class_labels", [])

        table = Table(title="Per-Class Performance")
        table.add_column("Severity", style="bold")
        table.add_column("Precision", justify="right")
        table.add_column("Recall", justify="right")
        table.add_column("F1-Score", justify="right")
        table.add_column("Support", justify="right")
        if "confidence_by_class" in metrics:
            table.add_column("Avg Confidence", justify="right")

        for label in class_labels:
            if label in report:
                cls = report[label]
                style = {
                    "critical": "red",
                    "high": "yellow",
                    "medium": "cyan",
                    "low": "blue",
                    "benign": "green",
                }.get(label, "")

                row = [
                    label.upper(),
                    f"{cls['precision']:.3f}",
                    f"{cls['recall']:.3f}",
                    f"{cls['f1-score']:.3f}",
                    str(int(cls['support'])),
                ]
                if "confidence_by_class" in metrics:
                    conf = metrics["confidence_by_class"].get(label, 0)
                    row.append(f"{conf:.3f}")

                table.add_row(*row, style=style)

        console.print(table)

    def _print_confusion_matrix(self, metrics: dict[str, Any]) -> None:
        """Print confusion matrix as a formatted table."""
        cm = metrics.get("confusion_matrix", [])
        labels = metrics.get("class_labels", [])

        if not cm or not labels:
            return

        table = Table(title="Confusion Matrix (rows=actual, cols=predicted)")
        table.add_column("", style="bold")
        for label in labels:
            table.add_column(label[:6].upper(), justify="right")

        for i, label in enumerate(labels):
            row = [label.upper()]
            for j in range(len(labels)):
                val = cm[i][j] if i < len(cm) and j < len(cm[i]) else 0
                style = "bold green" if i == j else ("red" if val > 0 else "dim")
                row.append(f"[{style}]{val}[/]")
            table.add_row(*row)

        console.print(table)

    def _print_feature_importance(self, top_n: int = 10) -> None:
        """Print top feature importances as a horizontal bar chart."""
        try:
            importances = self.trainer.get_feature_importance(top_n=top_n)
        except RuntimeError:
            return

        table = Table(title=f"Top {top_n} Feature Importances")
        table.add_column("Feature", style="bold")
        table.add_column("Importance", justify="right")
        table.add_column("Bar", min_width=30)

        max_imp = importances[0]["importance"] if importances else 1

        for item in importances:
            bar_len = int((item["importance"] / max_imp) * 30)
            bar = "█" * bar_len + "░" * (30 - bar_len)
            table.add_row(
                item["feature"],
                f"{item['importance']:.4f}",
                f"[cyan]{bar}[/]",
            )

        console.print(table)

    def save_report(self, output_dir: str | Path) -> Path:
        """Save evaluation report as a JSON file."""
        import json

        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        report_path = output_dir / "evaluation_report.json"
        report_data = {
            "model_type": self.trainer.model_type,
            "training_metadata": self.trainer.training_metadata,
            "feature_importance": self.trainer.get_feature_importance(top_n=20),
        }

        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info("report_saved", path=str(report_path))
        return report_path
