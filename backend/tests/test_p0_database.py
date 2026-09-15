"""
P0 — Database Models & Session Management
==========================================
Critical: ensure all ORM models are correct and sessions work.
"""

import datetime
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from database import (
    Base, User, Job, AuditLog, FirewallRule, Incident, IncidentNote,
    BackgroundTask, Experiment, CustomPlaybook, init_db,
)


@pytest.fixture
def fresh_engine():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session(fresh_engine):
    SessionLocal = sessionmaker(bind=fresh_engine)
    s = SessionLocal()
    yield s
    s.close()


class TestTableCreation:
    """Verify all expected tables are created."""

    def test_all_tables_exist(self, fresh_engine):
        inspector = inspect(fresh_engine)
        tables = set(inspector.get_table_names())
        expected = {
            "users", "jobs", "audit_logs", "firewall_rules",
            "incidents", "incident_notes", "background_tasks",
            "experiments", "custom_playbooks",
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"


class TestUserModel:
    def test_create_user(self, session):
        user = User(
            email="test@example.com",
            password_hash="fakehash",
            full_name="Test User",
            role="analyst",
        )
        session.add(user)
        session.commit()
        assert user.id is not None
        assert user.is_active is True
        assert user.role == "analyst"

    def test_user_email_unique(self, session):
        u1 = User(email="dup@example.com", password_hash="h1")
        u2 = User(email="dup@example.com", password_hash="h2")
        session.add(u1)
        session.commit()
        session.add(u2)
        with pytest.raises(Exception):
            session.commit()

    def test_user_default_role(self, session):
        user = User(email="norole@example.com", password_hash="h")
        session.add(user)
        session.commit()
        assert user.role == "analyst"

    def test_user_created_at_auto(self, session):
        user = User(email="ts@example.com", password_hash="h")
        session.add(user)
        session.commit()
        assert user.created_at is not None


class TestJobModel:
    def test_create_job(self, session):
        job = Job(
            id="abc12345",
            filename="test.csv",
            format_detected="cic-iot-2023",
            n_flows=100,
            n_threats=5,
            model_used="surrogate",
        )
        session.add(job)
        session.commit()
        assert job.id == "abc12345"

    def test_job_user_relationship(self, session):
        user = User(email="jobuser@example.com", password_hash="h")
        session.add(user)
        session.flush()
        job = Job(id="rel12345", user_id=user.id, filename="f.csv",
                  format_detected="csv", n_flows=10, model_used="surrogate")
        session.add(job)
        session.commit()
        assert job.user_id == user.id


class TestAuditLogModel:
    def test_create_audit_log(self, session):
        log = AuditLog(action="LOGIN", resource="session", details="ok", ip_address="127.0.0.1")
        session.add(log)
        session.commit()
        assert log.id is not None
        assert log.timestamp is not None


class TestFirewallRuleModel:
    def test_create_rule(self, session):
        job = Job(id="fw123456", filename="f.csv", format_detected="csv",
                  n_flows=10, model_used="surrogate")
        session.add(job)
        session.flush()
        rule = FirewallRule(
            job_id=job.id, rule_type="iptables", source_ip="10.0.0.1",
            action="DROP", threat_label="DDoS", severity="high",
            confidence=0.95, rule_text="iptables -A INPUT -s 10.0.0.1 -j DROP",
        )
        session.add(rule)
        session.commit()
        assert rule.id is not None


class TestIncidentModel:
    def test_create_incident(self, session):
        incident = Incident(
            incident_id="INC-001",
            playbook_id="PB-DDOS",
            playbook_name="DDoS Mitigation",
            severity="critical",
            source_ip="10.0.0.1",
        )
        session.add(incident)
        session.commit()
        assert incident.id is not None

    def test_incident_notes_relationship(self, session):
        incident = Incident(
            incident_id="INC-002",
            playbook_id="PB-RECON",
            playbook_name="Recon Response",
            severity="high",
        )
        session.add(incident)
        session.flush()
        note = IncidentNote(
            incident_id="INC-002",
            author="admin",
            note="Investigated and confirmed",
        )
        session.add(note)
        session.commit()
        assert len(incident.notes) == 1


class TestBackgroundTaskModel:
    def test_create_task(self, session):
        task = BackgroundTask(
            task_id="task12345678",
            task_type="ablation",
            name="Ablation study",
            status="queued",
        )
        session.add(task)
        session.commit()
        assert task.progress == 0


class TestExperimentModel:
    def test_create_experiment(self, session):
        exp = Experiment(
            experiment_id="exp123456",
            name="Baseline test",
            tags=["baseline", "v1"],
            task_type="prediction",
            model_used="surrogate",
        )
        session.add(exp)
        session.commit()
        assert exp.id is not None
        assert exp.tags == ["baseline", "v1"]


class TestCustomPlaybookModel:
    def test_create_playbook(self, session):
        pb = CustomPlaybook(
            playbook_key="custom-ddos",
            name="Custom DDoS",
            trigger_classes=["DDoS"],
            severity="critical",
        )
        session.add(pb)
        session.commit()
        assert pb.id is not None
