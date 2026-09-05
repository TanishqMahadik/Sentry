"""Pure-Python logistic regression for the Sentry ML advisory scorer.

Implements binary and one-vs-rest multiclass logistic regression using
gradient descent with L2 regularization and feature standardization.
Strictly stdlib-only (NFR-3) — no numpy, no scikit-learn.

The predictions are ADVISORY ONLY: they never gate or override the
rule-based detection path (detect/) or the mitigation engine (mitigate/).
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any


def sigmoid(x: float) -> float:
    """Numerically-stable logistic sigmoid.

    Args:
        x: Raw logit value

    Returns:
        Sigmoid output in the open interval (0, 1)
    """
    if x >= 0.0:
        return 1.0 / (1.0 + math.exp(-x))
    e = math.exp(x)
    return e / (1.0 + e)


class LogisticRegression:
    """Logistic regression classifier (binary + one-vs-rest multiclass).

    Attributes:
        feature_names: Optional ordered feature names for explainability.
    """

    def __init__(self) -> None:
        """Initialize an untrained classifier."""
        self.feature_names: list[str] | None = None
        self._classes: list[str] = []
        self._feature_count = 0
        self._weights: dict[str, list[float]] = {}
        self._intercepts: dict[str, float] = {}
        self._means: list[float] = []
        self._stds: list[float] = []
        self._binary = False
        self._positive_outcome = ""

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def fit(
        self,
        features: list[list[float]],
        labels: list[str],
        *,
        l2: float = 1e-3,
        learning_rate: float = 0.5,
        epochs: int = 800,
        standardize: bool = True,
        positive_outcome: str = "attack",
    ) -> dict[str, float]:
        """Fit the classifier to labeled feature vectors.

        Multiclass is handled with one-vs-rest: one binary logistic
        regression is fit per class ("class" vs "everything else").

        Args:
            features: List of feature vectors (n_samples x n_features)
            labels: Class label for each row
            l2: L2 regularization strength
            learning_rate: Gradient descent step size
            epochs: Gradient descent iterations
            standardize: Zero-mean / unit-variance feature scaling
            positive_outcome: Class used as the "positive" outcome for
                `predict_proba` in binary mode

        Returns:
            Dict of training metrics (accuracy, epochs, feature_count)

        Raises:
            ValueError: If inputs are empty, ragged, or mis-sized
        """
        if not features or not labels:
            raise ValueError("Cannot fit on empty feature/label data")
        if len(features) != len(labels):
            raise ValueError("Features and labels must have equal length")

        n_features = len(features[0])
        # Validate homogeneous widths
        for row in features:
            if len(row) != n_features:
                raise ValueError("Ragged feature vectors")

        self._feature_count = n_features
        self._classes = sorted(set(labels))
        self._binary = len(self._classes) == 2
        self._positive_outcome = (
            positive_outcome if positive_outcome in self._classes else self._classes[-1]
        )

        # Feature standardization (fit on training data)
        if standardize:
            self._means, self._stds = self._compute_scale(features)
        else:
            self._means = [0.0] * n_features
            self._stds = [1.0] * n_features
        z = [self._transform_features(row) for row in features]

        # One-vs-rest: fit a binary logistic regression per class
        for cls in self._classes:
            binary_labels = [1.0 if label == cls else 0.0 for label in labels]
            w, b = self._fit_binary(z, binary_labels, l2, learning_rate, epochs)
            self._weights[cls] = w
            self._intercepts[cls] = b

        # Training accuracy
        predictions = [self.predict(row) for row in features]
        correct = sum(1 for p, label in zip(predictions, labels) if p == label)
        return {
            "accuracy": correct / len(labels),
            "epochs": epochs,
            "feature_count": n_features,
        }

    @staticmethod
    def _compute_scale(features: list[list[float]]) -> tuple[list[float], list[float]]:
        """Compute per-feature mean and standard deviation."""
        n = len(features)
        n_features = len(features[0])
        means = [0.0] * n_features
        for row in features:
            for j, value in enumerate(row):
                means[j] += value
        means = [m / n for m in means]

        variances = [0.0] * n_features
        for row in features:
            for j, value in enumerate(row):
                variances[j] += (value - means[j]) ** 2
        stds = [math.sqrt(v / max(n - 1, 1)) for v in variances]
        # Guard against zero variance (constant feature)
        stds = [s if s > 1e-12 else 1.0 for s in stds]
        return means, stds

    def _fit_binary(
        self,
        z: list[list[float]],
        y: list[float],
        l2: float,
        learning_rate: float,
        epochs: int,
    ) -> tuple[list[float], float]:
        """Fit one binary logistic regression via gradient descent."""
        n = len(z)
        w = [0.0] * self._feature_count
        b = 0.0

        for _ in range(epochs):
            grad_w = [0.0] * self._feature_count
            grad_b = 0.0
            for xi, yi in zip(z, y):
                zlogit = self._dot(xi, w) + b
                p = sigmoid(zlogit)
                error = p - yi
                for j in range(self._feature_count):
                    grad_w[j] += error * xi[j]
                grad_b += error

            for j in range(self._feature_count):
                # L2 penalty on weights (intercept is unregularized)
                w[j] -= learning_rate * (grad_w[j] / n + l2 * w[j])
            b -= learning_rate * (grad_b / n)

        return w, b

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------
    def _transform_features(self, features: list[float]) -> list[float]:
        """Standardize a feature vector using the training scale."""
        size = min(len(features), self._feature_count)
        out = [0.0] * self._feature_count
        for j in range(size):
            out[j] = (features[j] - self._means[j]) / self._stds[j]
        return out

    @staticmethod
    def _dot(a: Iterable[float], b: Iterable[float]) -> float:
        return sum(x * y for x, y in zip(a, b))

    def _class_logit(self, class_label: str, features: list[float]) -> float:
        """Raw logit for one class."""
        if class_label not in self._weights:
            raise KeyError(f"Unknown class: {class_label}")
        return self._dot(features, self._weights[class_label]) + self._intercepts[class_label]

    def predict_probabilities(self, features: list[float]) -> dict[str, float]:
        """Per-class sigmoid probabilities.

        Args:
            features: Raw (unstandardized) feature vector

        Returns:
            Mapping of class label to sigmoid probability
        """
        z = self._transform_features(features)
        return {
            cls: sigmoid(self._class_logit(cls, z)) for cls in self._classes
        }

    def predict_proba(self, features: list[float]) -> float:
        """Advisory attack probability in (0, 1).

        - Binary mode: sigmoid probability of the positive outcome class.
        - Multiclass with a "benign" class: 1 minus the benign probability.
        - Otherwise: highest sigmoid probability across classes.

        Args:
            features: Raw (unstandardized) feature vector

        Returns:
            Probability in the open interval (0, 1)
        """
        z = self._transform_features(features)
        if self._binary:
            return sigmoid(self._class_logit(self._positive_outcome, z))
        if "benign" in self._classes:
            benign_p = sigmoid(self._class_logit("benign", z))
            return max(0.0, min(1.0, 1.0 - benign_p))
        return max(sigmoid(self._class_logit(cls, z)) for cls in self._classes)

    def predict(self, features: list[float]) -> str:
        """Predicted class via argmax over one-vs-rest sigmoids.

        Args:
            features: Raw (unstandardized) feature vector

        Returns:
            Predicted class label
        """
        z = self._transform_features(features)
        best_class = self._classes[0]
        best_prob = -1.0
        for cls in self._classes:
            prob = sigmoid(self._class_logit(cls, z))
            if prob > best_prob:
                best_prob = prob
                best_class = cls
        return best_class

    def top_features(self, features: list[float], k: int = 3) -> list[tuple[str, float]]:
        """Explainability: the k highest-magnitude weight contributions.

        Contributions use the weights of the predicted class (or the
        positive outcome in binary mode).

        Args:
            features: Raw (unstandardized) feature vector
            k: Number of top features to return

        Returns:
            List of (feature_name_or_index, contribution) sorted descending
        """
        if not self._classes:
            return []
        cls = self.predict(features)
        if self._binary:
            cls = self._positive_outcome
        z = self._transform_features(features)
        weights = self._weights[cls]

        contributions = [
            (j, weights[j] * z[j]) for j in range(min(self._feature_count, len(z)))
        ]
        ordered = sorted(contributions, key=lambda item: abs(item[1]), reverse=True)
        top = ordered[:k]
        if self.feature_names is not None:
            return [(self.feature_names[j], c) for j, c in top if j < len(self.feature_names)]
        return [(str(j), c) for j, c in top]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def coefficients(self) -> dict[str, list[float]]:
        """Per-class coefficient vectors (alias for weights)."""
        return dict(self._weights)

    def intercept(self) -> dict[str, float]:
        """Per-class intercepts."""
        return dict(self._intercepts)

    def scale(self) -> tuple[list[float], list[float]]:
        """Per-feature means and standard deviations."""
        return list(self._means), list(self._stds)

    def classes(self) -> list[str]:
        """Sorted class labels."""
        return list(self._classes)

    def set_feature_names(self, names: list[str]) -> None:
        """Attach feature names for explainability output."""
        self.feature_names = list(names)

    def get_params(self) -> dict[str, Any]:
        """Parameter dict consumable by ModelWeights."""
        return {
            "features": list(self.feature_names) if self.feature_names else [],
            "classes": self.classes(),
            "coefficients": self.coefficients(),
            "intercepts": self.intercept(),
            "means": self._means,
            "stds": self._stds,
        }

    @classmethod
    def restore(cls, params: dict[str, Any]) -> LogisticRegression:
        """Rebuild a trained classifier from persisted parameters.

        Args:
            params: Dict with ``features``, ``classes``, ``coefficients``,
                ``intercepts``, ``means``, and ``stds`` keys

        Returns:
            A fitted LogisticRegression ready for inference
        """
        model = cls()
        model.feature_names = list(params.get("features", []))
        model._classes = list(params["classes"])
        model._feature_count = max(len(model.feature_names), 1)
        coefficients = {
            str(k): [float(v) for v in vals] for k, vals in params["coefficients"].items()
        }
        model._weights = coefficients
        model._intercepts = {str(k): float(v) for k, v in params["intercepts"].items()}
        model._means = [float(v) for v in params.get("means", [0.0] * model._feature_count)]
        default_stds = [1.0] * model._feature_count
        model._stds = [
            float(v) if float(v) > 1e-12 else 1.0 for v in params.get("stds", default_stds)
        ]
        model._binary = len(model._classes) == 2
        model._positive_outcome = "attack" if "attack" in model._classes else model._classes[-1]
        return model
