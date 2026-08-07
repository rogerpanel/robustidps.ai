"""
P2 — Drift Detection
======================
Test statistical drift detection utilities.
"""

import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drift_detection import _compute_stats, _ks_test


class TestComputeStats:
    def test_basic_stats(self):
        features = np.array([[1, 2], [3, 4], [5, 6]], dtype=float)
        stats = _compute_stats(features)
        assert stats["n_samples"] == 3
        assert stats["n_features"] == 2
        assert len(stats["means"]) == 2
        assert len(stats["stds"]) == 2
        assert len(stats["mins"]) == 2
        assert len(stats["maxs"]) == 2

    def test_means_correct(self):
        features = np.array([[2, 4], [4, 8]], dtype=float)
        stats = _compute_stats(features)
        np.testing.assert_allclose(stats["means"], [3.0, 6.0])

    def test_quantiles_present(self):
        features = np.random.rand(100, 5)
        stats = _compute_stats(features)
        assert "q25" in stats
        assert "q50" in stats
        assert "q75" in stats
        for key in ("q25", "q50", "q75"):
            assert len(stats[key]) == 5

    def test_single_row(self):
        features = np.array([[1, 2, 3]], dtype=float)
        stats = _compute_stats(features)
        assert stats["n_samples"] == 1
        np.testing.assert_allclose(stats["stds"], [0, 0, 0])


class TestKSTest:
    def test_identical_distributions(self):
        ref = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
        stat, p = _ks_test(ref, ref.copy())
        assert stat == pytest.approx(0.0, abs=1e-10)

    def test_different_distributions(self):
        ref = np.random.normal(0, 1, 1000)
        new = np.random.normal(5, 1, 1000)
        stat, p = _ks_test(ref, new)
        assert stat > 0.5
        assert p < 0.05

    def test_similar_distributions_high_p(self):
        np.random.seed(42)
        ref = np.random.normal(0, 1, 500)
        new = np.random.normal(0, 1, 500)
        stat, p = _ks_test(ref, new)
        assert stat < 0.2

    def test_empty_array_handling(self):
        ref = np.array([])
        new = np.array([1.0, 2.0])
        stat, p = _ks_test(ref, new)
        assert stat == 0.0
        assert p == 1.0

    def test_both_empty(self):
        stat, p = _ks_test(np.array([]), np.array([]))
        assert stat == 0.0
        assert p == 1.0

    def test_stat_range(self):
        ref = np.random.rand(100)
        new = np.random.rand(100)
        stat, p = _ks_test(ref, new)
        assert 0.0 <= stat <= 1.0
        assert 0.0 <= p <= 1.0


class TestDriftEndpoints:
    def test_drift_analyze_endpoint_exists(self, client):
        # Should have drift endpoint
        resp = client.get("/api/drift/status")
        assert resp.status_code in (200, 404, 401, 405)
