"""
P2 — Post-Quantum Cryptography
================================
Test PQ algorithm registry and endpoints.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pq_crypto import PQ_ALGORITHMS


class TestPQAlgorithmRegistry:
    def test_registry_not_empty(self):
        assert len(PQ_ALGORITHMS) > 0

    def test_kyber512_exists(self):
        assert "kyber512" in PQ_ALGORITHMS

    def test_kyber768_exists(self):
        assert "kyber768" in PQ_ALGORITHMS

    def test_algorithm_structure(self):
        for alg_id, alg in PQ_ALGORITHMS.items():
            assert "name" in alg, f"{alg_id} missing name"
            assert "type" in alg, f"{alg_id} missing type"
            assert "nist_level" in alg, f"{alg_id} missing nist_level"
            assert alg["type"] in ("KEM", "Signature"), f"{alg_id} invalid type: {alg['type']}"

    def test_nist_levels_valid(self):
        for alg_id, alg in PQ_ALGORITHMS.items():
            assert alg["nist_level"] in (1, 2, 3, 4, 5), f"{alg_id} invalid NIST level"

    def test_kem_has_key_sizes(self):
        kems = {k: v for k, v in PQ_ALGORITHMS.items() if v["type"] == "KEM"}
        for alg_id, alg in kems.items():
            assert "pk_bytes" in alg, f"{alg_id} missing pk_bytes"
            assert "sk_bytes" in alg, f"{alg_id} missing sk_bytes"
            assert alg["pk_bytes"] > 0

    def test_timing_fields_positive(self):
        for alg_id, alg in PQ_ALGORITHMS.items():
            if "keygen_us" in alg:
                assert alg["keygen_us"] > 0


class TestPQEndpoints:
    def test_algorithms_endpoint(self, client, admin_token):
        resp = client.get(
            "/api/pq/algorithms",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert ("algorithms" in data or "kem_algorithms" in data
                or isinstance(data, list))

    def test_risk_assessment(self, client):
        resp = client.get("/api/pq/risk-assessment")
        assert resp.status_code in (200, 401)

    def test_comparison_matrix(self, client):
        resp = client.get("/api/pq/comparison-matrix")
        assert resp.status_code in (200, 401)
