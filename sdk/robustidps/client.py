"""
RobustIDPS SDK Client — typed wrapper around the REST API.
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path
from typing import Any, Optional

import httpx


class APIError(Exception):
    """Raised when the RobustIDPS API returns an error."""

    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(f"HTTP {status}: {detail}")


class Client:
    """
    Synchronous client for the RobustIDPS.AI REST API.

    Args:
        base_url: Platform URL (e.g. ``https://robustidps.example.com``).
        token:    Pre-existing JWT token. If provided, ``login()`` is not needed.
        timeout:  Request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        token: Optional[str] = None,
        timeout: float = 300,
    ):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._http = httpx.Client(base_url=self.base_url, timeout=timeout)

    # ── Auth ─────────────────────────────────────────────────────────────

    def login(self, email: str, password: str) -> dict:
        """Authenticate and store the JWT token for subsequent requests."""
        data = self._post("/api/auth/login", json={"email": email, "password": password})
        self._token = data["token"]
        return data

    def me(self) -> dict:
        """Get current authenticated user info."""
        return self._get("/api/auth/me")

    # ── Core Prediction ──────────────────────────────────────────────────

    def predict(
        self,
        file: str | Path,
        model: Optional[str] = None,
        uncertainty: bool = False,
    ) -> dict:
        """
        Upload a CSV/PCAP file and run prediction.

        Args:
            file:        Path to CSV or PCAP file.
            model:       Model ID (surrogate, neural_ode, etc.). Defaults to active model.
            uncertainty: If True, use MC Dropout uncertainty quantification.

        Returns:
            dict with job_id, n_flows, n_threats, predictions, attack_distribution, etc.
        """
        endpoint = "/api/predict_uncertain" if uncertainty else "/api/predict"
        path = Path(file)
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            data = {}
            if model:
                data["model_name"] = model
            return self._post(endpoint, files=files, data=data)

    def upload(self, file: str | Path) -> dict:
        """Upload a file for later streaming/analysis. Returns job_id."""
        path = Path(file)
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            return self._post("/api/upload", files=files)

    def results(self, job_id: str) -> dict:
        """Retrieve prediction results for a previously uploaded job."""
        return self._get(f"/api/results/{job_id}")

    def export_csv(self, job_id: str, output: str | Path = "results.csv") -> Path:
        """Download prediction results as CSV."""
        resp = self._raw_get(f"/api/export/{job_id}")
        out = Path(output)
        out.write_bytes(resp.content)
        return out

    # ── Models ───────────────────────────────────────────────────────────

    def models(self) -> dict:
        """List all available models with their status."""
        return self._get("/api/models")

    def activate_model(self, model_id: str) -> dict:
        """Switch the active model."""
        return self._post(f"/api/models/{model_id}/activate")

    def model_info(self) -> dict:
        """Get active model metadata."""
        return self._get("/api/model_info")

    # ── Ablation ─────────────────────────────────────────────────────────

    def ablation(
        self,
        file: str | Path,
        mode: str = "single",
        model: Optional[str] = None,
    ) -> dict:
        """
        Run ablation study on uploaded data.

        Args:
            file:  Path to CSV/PCAP file.
            mode:  "single", "pairwise", or "incremental".
            model: Model ID.
        """
        path = Path(file)
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            data = {"mode": mode}
            if model:
                data["model_name"] = model
            return self._post("/api/ablation", files=files, data=data)

    # ── Red Team Arena ───────────────────────────────────────────────────

    def redteam(
        self,
        file: str | Path,
        attacks: Optional[list[str]] = None,
        epsilon: float = 0.1,
        n_samples: int = 500,
        model: Optional[str] = None,
    ) -> dict:
        """
        Run adversarial robustness evaluation.

        Args:
            file:      Path to CSV/PCAP file.
            attacks:   List of attacks: fgsm, pgd, deepfool, gaussian, feature_mask.
            epsilon:   Perturbation budget.
            n_samples: Number of samples to test.
            model:     Model ID.
        """
        path = Path(file)
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            data: dict[str, Any] = {
                "epsilon": str(epsilon),
                "n_samples": str(n_samples),
            }
            if attacks:
                data["attacks"] = ",".join(attacks)
            if model:
                data["model_name"] = model
            return self._post("/api/redteam/run", files=files, data=data)

    # ── Explainability ───────────────────────────────────────────────────

    def explain(
        self,
        file: str | Path,
        method: str = "gradient_saliency",
        model: Optional[str] = None,
    ) -> dict:
        """Run XAI analysis. Methods: gradient_saliency, integrated_gradients, sensitivity."""
        path = Path(file)
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            data = {"method": method}
            if model:
                data["model_name"] = model
            return self._post("/api/xai/run", files=files, data=data)

    # ── Federated Learning ───────────────────────────────────────────────

    def federated(
        self,
        file: str | Path,
        strategy: str = "fedavg",
        n_clients: int = 5,
        rounds: int = 10,
        model: Optional[str] = None,
    ) -> dict:
        """Run federated learning simulation."""
        path = Path(file)
        with open(path, "rb") as f:
            files = {"file": (path.name, f)}
            data = {
                "strategy": strategy,
                "n_clients": str(n_clients),
                "rounds": str(rounds),
            }
            if model:
                data["model_name"] = model
            return self._post("/api/federated/run", files=files, data=data)

    # ── Experiments ──────────────────────────────────────────────────────

    def create_experiment(self, name: str, **kwargs) -> dict:
        """Create a new experiment record."""
        return self._post("/api/experiments", json={"name": name, **kwargs})

    def list_experiments(self, **filters) -> dict:
        """List experiments with optional filters (task_type, tag, search)."""
        return self._get("/api/experiments", params=filters)

    def compare_experiments(self, experiment_ids: list[str]) -> dict:
        """Compare 2-4 experiments side by side."""
        return self._get("/api/experiments/compare", params={"ids": ",".join(experiment_ids)})

    def experiment_manifest(self, experiment_id: str) -> dict:
        """Get reproducible experiment manifest."""
        return self._get(f"/api/experiments/{experiment_id}/manifest")

    # ── Reports ──────────────────────────────────────────────────────────

    def latex_comparison(self, experiment_ids: list[str]) -> str:
        """Generate LaTeX comparison table."""
        resp = self._raw_post(
            "/api/reports/latex/comparison",
            json={"experiment_ids": experiment_ids},
        )
        return resp.text

    def latex_experiment(self, experiment_id: str) -> str:
        """Generate LaTeX tables for a single experiment."""
        resp = self._raw_post(
            "/api/reports/latex/experiment",
            json={"experiment_id": experiment_id},
        )
        return resp.text

    def csv_report(self, experiment_ids: list[str], output: str | Path = "report.csv") -> Path:
        """Export experiments as CSV report."""
        resp = self._raw_post(
            "/api/reports/csv",
            json={"experiment_ids": experiment_ids},
        )
        out = Path(output)
        out.write_bytes(resp.content)
        return out

    # ── Tasks (Job Queue) ────────────────────────────────────────────────

    def list_tasks(self, status: Optional[str] = None) -> dict:
        """List background tasks."""
        params = {}
        if status:
            params["status"] = status
        return self._get("/api/tasks", params=params)

    def task_status(self, task_id: str) -> dict:
        """Get task status and result."""
        return self._get(f"/api/tasks/{task_id}")

    def wait_for_task(self, task_id: str, poll_interval: float = 2.0, timeout: float = 3600) -> dict:
        """Poll a task until completion or timeout."""
        start = time.time()
        while time.time() - start < timeout:
            result = self.task_status(task_id)
            if result["status"] in ("completed", "failed"):
                return result
            time.sleep(poll_interval)
        raise TimeoutError(f"Task {task_id} did not complete within {timeout}s")

    # ── Datasets ─────────────────────────────────────────────────────────

    def list_datasets(self) -> dict:
        """List available datasets."""
        return self._get("/api/datasets")

    def dataset_info(self, name: str) -> dict:
        """Get dataset metadata."""
        return self._get(f"/api/datasets/{name}/info")

    # ── Firewall Rules ───────────────────────────────────────────────────

    def generate_firewall_rules(self, job_id: str, rule_type: str = "iptables") -> dict:
        """Generate firewall rules from detection results."""
        return self._post("/api/firewall/generate", json={
            "job_id": job_id,
            "rule_type": rule_type,
        })

    # ── Health ───────────────────────────────────────────────────────────

    def health(self) -> dict:
        """Check API health."""
        return self._get("/api/health")

    # ── HTTP internals ───────────────────────────────────────────────────

    @property
    def _headers(self) -> dict:
        h: dict[str, str] = {}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _get(self, path: str, **kwargs) -> dict:
        resp = self._http.get(path, headers=self._headers, **kwargs)
        return self._handle(resp)

    def _post(self, path: str, **kwargs) -> dict:
        resp = self._http.post(path, headers=self._headers, **kwargs)
        return self._handle(resp)

    def _raw_get(self, path: str, **kwargs) -> httpx.Response:
        resp = self._http.get(path, headers=self._headers, **kwargs)
        if resp.status_code >= 400:
            raise APIError(resp.status_code, resp.text)
        return resp

    def _raw_post(self, path: str, **kwargs) -> httpx.Response:
        resp = self._http.post(path, headers=self._headers, **kwargs)
        if resp.status_code >= 400:
            raise APIError(resp.status_code, resp.text)
        return resp

    @staticmethod
    def _handle(resp: httpx.Response) -> dict:
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except Exception:
                detail = resp.text
            raise APIError(resp.status_code, str(detail))
        return resp.json()

    def close(self):
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
