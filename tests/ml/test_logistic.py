"""Tests for sentry.ml.logistic — pure-Python logistic regression."""

from __future__ import annotations

import unittest

from sentry.ml.logistic import LogisticRegression, sigmoid


def _separable_binary() -> tuple[list[list[float]], list[str]]:
    """Two perfectly separable 2-D clusters (attack positive side)."""
    features = [
        [5.0, 5.0],
        [6.0, 5.0],
        [5.0, 6.0],
        [-5.0, -5.0],
        [-6.0, -5.0],
        [-5.0, -6.0],
    ]
    labels = ["attack", "attack", "attack", "benign", "benign", "benign"]
    return features, labels


class TestSigmoid(unittest.TestCase):
    """Numerical properties of the sigmoid."""

    def test_bounds(self):
        self.assertAlmostEqual(sigmoid(-100.0), 0.0)
        self.assertAlmostEqual(sigmoid(100.0), 1.0)

    def test_center(self):
        self.assertAlmostEqual(sigmoid(0.0), 0.5)

    def test_monotonic(self):
        self.assertLess(sigmoid(-1.0), sigmoid(0.0))
        self.assertLess(sigmoid(0.0), sigmoid(1.0))

    def test_stable_on_extremes(self):
        # No overflow/underflow for large magnitudes.
        self.assertGreater(sigmoid(1e6), 0.999999)
        self.assertLess(sigmoid(-1e6), 0.000001)


class TestFitBinary(unittest.TestCase):
    """Training and inference on separable binary data."""

    def test_converges_perfectly(self):
        features, labels = _separable_binary()
        model = LogisticRegression()
        metrics = model.fit(features, labels, l2=0.0, learning_rate=1.0, epochs=2000)
        self.assertGreaterEqual(metrics["accuracy"], 0.99)

        predictions = [model.predict(x) for x in features]
        self.assertEqual(predictions, labels)

    def test_predict_proba_direction(self):
        features, labels = _separable_binary()
        model = LogisticRegression()
        model.fit(features, labels, l2=0.0, learning_rate=1.0, epochs=2000)
        self.assertGreater(model.predict_proba([6.0, 6.0]), 0.5)
        self.assertLess(model.predict_proba([-6.0, -6.0]), 0.5)

    def test_standardization_applied(self):
        features, labels = _separable_binary()
        model = LogisticRegression()
        model.fit(features, labels, epochs=100)
        means, stds = model.scale()
        # Cluster centers are +5 / -5 -> mean near 0, std near 5.
        self.assertAlmostEqual(means[0], 0.0, places=0)
        self.assertGreater(stds[0], 1.0)

    def test_l2_shrinks_weights(self):
        features, labels = _separable_binary()

        # l2=0.2 with lr=0.5 keeps the GD update stable (lr*l2 < 1).
        strong = LogisticRegression()
        strong.fit(features, labels, l2=0.2, learning_rate=0.5, epochs=1500)
        weak = LogisticRegression()
        weak.fit(features, labels, l2=0.0, learning_rate=0.5, epochs=1500)

        norm = lambda model: sum(  # noqa: E731
            abs(v) for vec in model.coefficients().values() for v in vec
        )
        self.assertLess(norm(strong), norm(weak))

    def test_positive_outcome_controls_proba(self):
        features, labels = _separable_binary()
        model = LogisticRegression()
        model.fit(features, labels, l2=0.0, learning_rate=1.0, epochs=2000)
        # Attack vector is positive; benign vector is negative.
        self.assertGreater(model.predict_proba([6.0, 6.0]), 0.5)
        self.assertLess(model.predict_proba([-6.0, -6.0]), 0.5)


class TestFitValidation(unittest.TestCase):
    """Input validation errors."""

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            LogisticRegression().fit([], [])

    def test_mismatched_length_raises(self):
        with self.assertRaises(ValueError):
            LogisticRegression().fit([[1.0]], ["a", "b"])

    def test_ragged_raises(self):
        with self.assertRaises(ValueError):
            LogisticRegression().fit([[1.0, 2.0], [3.0]], ["a", "b"])


class TestMulticlass(unittest.TestCase):
    """One-vs-rest multiclass classification."""

    def test_three_classes(self):
        features = [[1.0, 0.0], [1.1, 0.0], [0.0, 1.0], [0.0, 1.1], [-1.0, -1.0], [-1.1, -1.0]]
        labels = ["a", "a", "b", "b", "c", "c"]
        model = LogisticRegression()
        metrics = model.fit(features, labels, l2=0.0, learning_rate=1.0, epochs=2000)
        self.assertGreaterEqual(metrics["accuracy"], 0.99)
        predictions = [model.predict(x) for x in features]
        self.assertEqual(predictions, labels)
        self.assertEqual(sorted(model.classes()), ["a", "b", "c"])


class TestTopFeatures(unittest.TestCase):
    """Explainability output."""

    def test_returns_k_named_features(self):
        features, labels = _separable_binary()
        model = LogisticRegression()
        model.set_feature_names(["x", "y"])
        model.fit(features, labels, l2=0.0, learning_rate=1.0, epochs=2000)

        top = model.top_features([6.0, 6.0], k=2)
        self.assertEqual(len(top), 2)
        names = {name for name, _ in top}
        self.assertEqual(names, {"x", "y"})
        for _, contrib in top:
            self.assertIsInstance(contrib, float)

    def test_empty_before_fit(self):
        self.assertEqual(LogisticRegression().top_features([1.0, 2.0]), [])


class TestSerialization(unittest.TestCase):
    """get_params / restore roundtrip."""

    def test_restore_roundtrip(self):
        features, labels = _separable_binary()
        model = LogisticRegression()
        model.set_feature_names(["x", "y"])
        model.fit(features, labels, epochs=500)

        restored = LogisticRegression.restore(model.get_params())
        self.assertEqual(restored.classes(), model.classes())
        for x in features:
            self.assertEqual(restored.predict(x), model.predict(x))

    def test_restore_binary_positive_outcome(self):
        features, labels = _separable_binary()
        model = LogisticRegression()
        model.fit(features, labels, epochs=100, positive_outcome="attack")
        restored = LogisticRegression.restore(model.get_params())
        self.assertGreater(restored.predict_proba([6.0, 6.0]), 0.5)


if __name__ == "__main__":
    unittest.main()
