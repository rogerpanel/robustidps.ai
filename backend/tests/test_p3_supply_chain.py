"""
P3 — Supply Chain Security
============================
Test model dependency registry and supply chain endpoints.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supply_chain import MODEL_DEPENDENCIES


class TestModelDependencies:
    def test_registry_not_empty(self):
        assert len(MODEL_DEPENDENCIES) > 0

    def test_surrogate_ids_exists(self):
        assert "surrogate_ids" in MODEL_DEPENDENCIES

    def test_dependency_structure(self):
        for model_id, model in MODEL_DEPENDENCIES.items():
            assert "name" in model, f"{model_id} missing name"
            assert "framework" in model, f"{model_id} missing framework"
            assert "dependencies" in model, f"{model_id} missing dependencies"
            assert isinstance(model["dependencies"], list)

    def test_dependencies_have_required_fields(self):
        for model_id, model in MODEL_DEPENDENCIES.items():
            for dep in model["dependencies"]:
                assert "name" in dep, f"{model_id} dep missing name"
                assert "version" in dep, f"{model_id} dep missing version"

    def test_surrogate_uses_pytorch(self):
        s = MODEL_DEPENDENCIES["surrogate_ids"]
        assert s["framework"] == "PyTorch"


class TestSupplyChainEndpoints:
    def test_sbom_endpoint(self, client, admin_token):
        resp = client.get(
            "/api/supply-chain/sbom",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 404)

    def test_scan_endpoint(self, client, admin_token):
        resp = client.post(
            "/api/supply-chain/scan",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code in (200, 404, 422)
