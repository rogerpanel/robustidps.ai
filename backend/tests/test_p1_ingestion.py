"""
P1 — Ingestion Pipeline
========================
Test the IngestionStats tracker and ingestion endpoints.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ingestion import IngestionStats


class TestIngestionStats:
    def test_initial_state(self):
        stats = IngestionStats()
        assert stats.total_records == 0
        assert stats.total_threats == 0
        assert stats.records_per_source == {}
        assert stats.last_event_at is None

    def test_record_benign(self):
        stats = IngestionStats()
        stats.record("netflow", "Benign", 0.99, {"src_ip": "10.0.0.1"})
        assert stats.total_records == 1
        assert stats.total_threats == 0
        assert stats.records_per_source["netflow"] == 1

    def test_record_threat(self):
        stats = IngestionStats()
        stats.record("zeek", "DDoS", 0.85, {"src_ip": "10.0.0.1"})
        assert stats.total_records == 1
        assert stats.total_threats == 1
        assert stats.threat_distribution["DDoS"] == 1

    def test_multiple_records(self):
        stats = IngestionStats()
        for i in range(10):
            label = "Benign" if i < 7 else "DDoS"
            stats.record("netflow", label, 0.9, {})
        assert stats.total_records == 10
        assert stats.total_threats == 3
        assert stats.records_per_source["netflow"] == 10

    def test_to_dict(self):
        stats = IngestionStats()
        stats.record("syslog", "Recon", 0.8, {"src_ip": "1.2.3.4"})
        d = stats.to_dict()
        assert d["total_records"] == 1
        assert d["total_threats"] == 1
        assert "recent_events" in d
        assert len(d["recent_events"]) == 1

    def test_recent_events_capped(self):
        stats = IngestionStats()
        for i in range(150):
            stats.record("test", "Benign", 0.9, {})
        d = stats.to_dict()
        assert len(d["recent_events"]) <= 20

    def test_multiple_sources(self):
        stats = IngestionStats()
        stats.record("netflow", "Benign", 0.9, {})
        stats.record("zeek", "DDoS", 0.8, {})
        stats.record("syslog", "Benign", 0.95, {})
        assert len(stats.records_per_source) == 3

    def test_last_event_at_updates(self):
        stats = IngestionStats()
        stats.record("netflow", "Benign", 0.9, {})
        first = stats.last_event_at
        assert first is not None
        stats.record("netflow", "DDoS", 0.8, {})
        assert stats.last_event_at is not None


class TestIngestionEndpoints:
    def test_ingest_status(self, client):
        resp = client.get("/api/ingest/status")
        assert resp.status_code in (200, 401, 404)
