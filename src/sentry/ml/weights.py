"""Serializable model weights for the Sentry ML advisory scorer.

The trained LogisticRegression is persisted to a single JSON file so the
scorer works fully offline with zero runtime dependencies (NFR-3).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Version marker embedded in the artifact for forward-compat checks.
MODEL_VERSION = "advisory-logistic-v1"

_REQUIRED_KEYS = (
    "model_version",
    "features",
    "classes",
    "coefficients",
    "intercepts",
    "means",
    "stds",
    "trained_at",
)


@dataclass
class ModelWeights:
    """Persisted logistic regression parameters + metadata.

    Attributes:
        features: Ordered feature names (must match FEATURE_ORDER at scoring)
        classes: Sorted class labels
        coefficients: Per-class coefficient vectors
        intercepts: Per-class intercepts
        means: Per-feature standardization means
        stds: Per-feature standardization standard deviations
        trained_at: Unix epoch seconds of training
        metrics: Training/validation metrics (accuracy, etc.)
        model_version: Artifact version marker
    """

    features: list[str]
    classes: list[str]
    coefficients: dict[str, list[float]]
    intercepts: dict[str, float]
    means: list[float]
    stds: list[float]
    trained_at: int
    metrics: dict[str, float] = field(default_factory=dict)
    model_version: str = MODEL_VERSION

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        return {
            "model_version": self.model_version,
            "features": list(self.features),
            "classes": list(self.classes),
            "coefficients": {k: [float(v) for v in vals] for k, vals in self.coefficients.items()},
            "intercepts": {k: float(v) for k, v in self.intercepts.items()},
            "means": [float(v) for v in self.means],
            "stds": [float(v) for v in self.stds],
            "trained_at": int(self.trained_at),
            "metrics": dict(self.metrics),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModelWeights:
        """Deserialize, validating required structure.

        Args:
            data: Dict produced by :meth:`to_dict`

        Returns:
            A ModelWeights instance

        Raises:
            ValueError: If a required key is missing or mis-typed
        """
        for key in _REQUIRED_KEYS:
            if key not in data:
                raise ValueError(f"Model weights missing required key: {key}")

        coefficients = {
            str(k): [float(v) for v in vals] for k, vals in data["coefficients"].items()
        }
        intercepts = {str(k): float(v) for k, v in data["intercepts"].items()}
        means = [float(v) for v in data["means"]]
        stds = [float(v) for v in data["stds"]]

        features = [str(f) for f in data["features"]]
        classes = [str(c) for c in data["classes"]]
        if not features:
            raise ValueError("Model weights require a non-empty feature list")
        if not classes:
            raise ValueError("Model weights require a non-empty class list")

        return cls(
            features=features,
            classes=classes,
            coefficients=coefficients,
            intercepts=intercepts,
            means=means,
            stds=stds,
            trained_at=int(data["trained_at"]),
            metrics={str(k): float(v) for k, v in data.get("metrics", {}).items()},
            model_version=str(data["model_version"]),
        )

    def save(self, path: str | Path) -> None:
        """Write weights to a JSON file.

        Args:
            path: Destination file path
        """
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)

    @classmethod
    def load(cls, path: str | Path) -> ModelWeights:
        """Load weights from a JSON file.

        Args:
            path: Source file path

        Returns:
            A ModelWeights instance

        Raises:
            FileNotFoundError: If the file does not exist
            ValueError: If the JSON is malformed or structurally invalid
        """
        source = Path(path)
        try:
            with open(source, encoding="utf-8") as handle:
                raw = handle.read()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise ValueError(f"Cannot read weights file {source}: {exc}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed weights file {source}: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError(f"Malformed weights file {source}: expected a JSON object")

        return cls.from_dict(data)


def weights_from_model(
    model: Any,
    features: list[str],
    trained_at: int | None = None,
    metrics: dict[str, float] | None = None,
) -> ModelWeights:
    """Build ModelWeights from a fitted LogisticRegression.

    Args:
        model: Fitted LogisticRegression exposing ``get_params()``
        features: Ordered feature names
        trained_at: Override timestamp (defaults to now)
        metrics: Optional metrics dict to persist

    Returns:
        A ModelWeights instance ready to be saved
    """
    params = model.get_params()
    params.setdefault("features", list(features))
    return ModelWeights(
        features=list(features),
        classes=params["classes"],
        coefficients=params["coefficients"],
        intercepts=params["intercepts"],
        means=params["means"],
        stds=params["stds"],
        trained_at=int(trained_at if trained_at is not None else time.time()),
        metrics=dict(metrics or {}),
    )
