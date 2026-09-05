"""Tests for sentry.ml.weights — ModelWeights persistence."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentry.ml.weights import MODEL_VERSION, ModelWeights, weights_from_model


def _sample_weights() -> ModelWeights:
    return ModelWeights(
        features=["a", "b", "c"],
        classes=["attack", "benign"],
        coefficients={"attack": [1.0, 2.0, 3.0], "benign": [-1.0, -2.0, -3.0]},
        intercepts={"attack": 0.5, "benign": -0.5},
        means=[10.0, 20.0, 30.0],
        stds=[1.0, 2.0, 3.0],
        trained_at=12345,
        metrics={"accuracy": 0.95},
    )


class TestRoundtrip(unittest.TestCase):
    """save/load equality."""

    def test_roundtrip_preserves_all_fields(self):
        original = _sample_weights()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "weights.json"
            original.save(path)

            loaded = ModelWeights.load(path)
        self.assertEqual(loaded.features, original.features)
        self.assertEqual(loaded.classes, original.classes)
        self.assertEqual(loaded.coefficients, original.coefficients)
        self.assertEqual(loaded.intercepts, original.intercepts)
        self.assertEqual(loaded.means, original.means)
        self.assertEqual(loaded.stds, original.stds)
        self.assertEqual(loaded.trained_at, original.trained_at)
        self.assertEqual(loaded.metrics, original.metrics)
        self.assertEqual(loaded.model_version, original.model_version)

    def test_save_creates_parent_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "dir" / "weights.json"
            _sample_weights().save(path)
            self.assertTrue(path.is_file())

    def test_to_dict_contains_version(self):
        data = _sample_weights().to_dict()
        self.assertEqual(data["model_version"], MODEL_VERSION)


class TestLoadValidation(unittest.TestCase):
    """Error handling for malformed weights."""

    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            ModelWeights.load("does-not-exist.json")

    def test_missing_key_raises_value_error(self):
        data = _sample_weights().to_dict()
        del data["stds"]
        with self.assertRaises(ValueError):
            ModelWeights.from_dict(data)

    def test_corrupt_json_raises_value_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "weights.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                ModelWeights.load(path)

    def test_non_object_json_raises_value_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "weights.json"
            path.write_text("[1, 2, 3]", encoding="utf-8")
            with self.assertRaises(ValueError):
                ModelWeights.load(path)

    def test_empty_features_raises(self):
        data = _sample_weights().to_dict()
        data["features"] = []
        with self.assertRaises(ValueError):
            ModelWeights.from_dict(data)

    def test_empty_classes_raises(self):
        data = _sample_weights().to_dict()
        data["classes"] = []
        with self.assertRaises(ValueError):
            ModelWeights.from_dict(data)


class TestWeightsFromModel(unittest.TestCase):
    """Helper converting a fitted model into weights."""

    def test_builds_from_fitted_model(self):
        from sentry.ml.logistic import LogisticRegression

        model = LogisticRegression()
        model.set_feature_names(["x", "y"])
        model.fit([[1.0, 1.0], [-1.0, -1.0]], ["attack", "benign"], epochs=10)

        weights = weights_from_model(model, features=["x", "y"], metrics={"accuracy": 1.0})
        self.assertEqual(weights.features, ["x", "y"])
        self.assertEqual(weights.metrics["accuracy"], 1.0)
        self.assertEqual(set(weights.classes), {"attack", "benign"})
        self.assertEqual(len(weights.coefficients["attack"]), 2)


if __name__ == "__main__":
    unittest.main()
