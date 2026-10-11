"""Stored BlueSec agent runs. Created by `init_db()` at boot like other plugins."""
from __future__ import annotations

import datetime

from sqlalchemy import JSON, Column, DateTime, Float, ForeignKey, Integer, String, Text

from database import Base


class BlueSecRun(Base):
    __tablename__ = "bluesec_runs"

    id = Column(String(32), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    notes = Column(Text, default="")
    source = Column(String(300), default="upload")       # "upload" | "server:<folder>"
    pt_run_id = Column(String(255), default="")
    agent_model = Column(String(255), default="")
    started_at = Column(DateTime, nullable=True)            # from the trace folder name
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False, index=True)
    n_tasks = Column(Integer, default=0)
    n_completed = Column(Integer, default=0)
    mean_quality = Column(Float, default=0.0)
    mean_efficiency = Column(Float, default=0.0)
    mean_reward = Column(Float, default=0.0)
    mean_tool_calls = Column(Float, default=0.0)
    label = Column(String(255), nullable=True)              # configuration name (ablation row)
    config = Column(JSON, nullable=True)                    # agent settings recorded by the run
    metrics = Column(JSON, nullable=True)                   # overall / by_platform / by_expected_verdict
    payload = Column(JSON, nullable=False)                  # {"tasks": [...], "aggregates": {...}}
