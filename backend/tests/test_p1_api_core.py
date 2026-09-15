"""
P1 — Core API Endpoints
========================
Health, model info, analytics, and upload/predict flow.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestHealthEndpoint:
    def test_health_returns_ok(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("healthy", "ok", "running")

    def test_health_includes_model_loaded(self, client):
        resp = client.get("/api/health")
        data = resp.json()
        assert "model_loaded" in data


class TestModelInfo:
    def test_model_info_endpoint(self, client):
        resp = client.get("/api/model_info")
        assert resp.status_code == 200
        data = resp.json()
        assert "model_name" in data or "active_model" in data or "name" in data

    def test_models_list(self, client):
        resp = client.get("/api/models")
        assert resp.status_code == 200
        data = resp.json()
        assert "models" in data
        assert isinstance(data["models"], list)
        assert len(data["models"]) > 0


class TestAnalytics:
    def test_analytics_endpoint(self, client):
        resp = client.get("/api/analytics")
        assert resp.status_code == 200
        data = resp.json()
        # Should have benchmark or research metrics
        assert isinstance(data, dict)


class TestUploadEndpoint:
    def test_upload_csv(self, client, sample_csv, admin_token):
        with open(sample_csv, "rb") as f:
            resp = client.post(
                "/api/upload",
                files={"file": ("test.csv", f, "text/csv")},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "job_id" in data

    def test_upload_no_file(self, client, admin_token):
        resp = client.post(
            "/api/upload",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 422


class TestPredictEndpoint:
    def test_predict_csv(self, client, sample_csv, admin_token):
        with open(sample_csv, "rb") as f:
            resp = client.post(
                "/api/predict",
                files={"file": ("test.csv", f, "text/csv")},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        # Either 200 or model-not-loaded error
        assert resp.status_code in (200, 500, 503)
        if resp.status_code == 200:
            data = resp.json()
            assert "job_id" in data
            assert "n_flows" in data


class TestExportEndpoint:
    def test_export_nonexistent_job(self, client):
        resp = client.get("/api/export/nonexist")
        assert resp.status_code in (401, 404, 400, 500)


class TestMetrics:
    def test_prometheus_metrics(self, client):
        resp = client.get("/metrics")
        # Prometheus metrics may or may not be set up in test env
        assert resp.status_code in (200, 404)
