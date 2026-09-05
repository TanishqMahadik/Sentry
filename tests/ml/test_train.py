"""Tests for sentry.ml.train — dataset synthesis and training pipeline."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentry.ml.advisory import FEATURE_ORDER
from sentry.ml.train import CLASSES, build_dataset, evaluate, main, train
from sentry.ml.weights import ModelWeights


class TestDataset(unittest.TestCase):
    """Synthetic data generation."""

    def test_all_nine_labels_present(self):
        vectors, labels, samples = build_dataset(samples_per_class=4, seed=7)
        self.assertEqual(len(vectors), len(labels))
        self.assertEqual(set(labels), set(CLASSES))
        self.assertEqual(len(CLASSES), 9)
        for vector in vectors:
            self.assertEqual(len(vector), len(FEATURE_ORDER))

    def test_deterministic_under_seed(self):
        v1, l1, _ = build_dataset(samples_per_class=5, seed=7)
        v2, l2, _ = build_dataset(samples_per_class=5, seed=7)
        self.assertEqual(v1, v2)
        self.assertEqual(l1, l2)

    def test_different_seeds_differ(self):
        v1, _, _ = build_dataset(samples_per_class=5, seed=1)
        v2, _, _ = build_dataset(samples_per_class=5, seed=2)
        self.assertNotEqual(v1, v2)


class TestEvaluate(unittest.TestCase):
    """Confusion-matrix metrics."""

    def test_perfect_classification(self):
        metrics = evaluate([("syn_flood", "syn_flood"), ("benign", "benign")])
        self.assertEqual(metrics["accuracy"], 1.0)
        self.assertEqual(metrics["precision"], 1.0)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["f1"], 1.0)

    def test_attack_detection_metrics(self):
        # (predicted, actual): one FP, one FN, two TP, one TN.
        metrics = evaluate(
            [
                ("syn_flood", "benign"),  # FP
                ("benign", "udp_flood"),  # FN
                ("syn_flood", "syn_flood"),
                ("udp_flood", "udp_flood"),
                ("benign", "benign"),
            ]
        )
        self.assertAlmostEqual(metrics["precision"], 2 / 3)
        self.assertAlmostEqual(metrics["recall"], 2 / 3)
        self.assertAlmostEqual(metrics["accuracy"], 3 / 5)

    def test_empty_returns_zero(self):
        metrics = evaluate([])
        self.assertEqual(metrics["accuracy"], 0.0)


class TestTrain(unittest.TestCase):
    """Fitting the full model on synthetic data."""

    def test_held_out_accuracy_high(self):
        model, val_metrics = train(samples_per_class=30, seed=7, epochs=400)
        self.assertGreaterEqual(val_metrics["accuracy"], 0.9)
        # Model can be serialized and restored.
        restored = type(model).restore(model.get_params())
        self.assertEqual(restored.classes(), model.classes())


class TestMain(unittest.TestCase):
    """End-to-end train-and-persist pipeline."""

    def test_writes_loadable_weights(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = str(Path(tmp) / "weights.json")
            code = main(samples=12, out=out, epochs=200, verbose=False)
            self.assertEqual(code, 0)
            weights = ModelWeights.load(out)
            self.assertEqual(weights.features, FEATURE_ORDER)
            self.assertEqual(set(weights.classes), set(CLASSES))
            self.assertIn("accuracy", weights.metrics)
            self.assertEqual(len(weights.coefficients["benign"]), len(FEATURE_ORDER))


if __name__ == "__main__":
    unittest.main()
