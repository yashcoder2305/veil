"""
tests/intelligence/test_trajectory.py
"""
from __future__ import annotations

import pytest
from veil.models.action import Action, DataClassification
from veil.security.trajectory import TrajectoryEngine


def _action(**kwargs) -> Action:
    defaults = dict(
        agent_id="agent-1",
        session_id="sess-1",
        tool="database",
        operation="read",
        resource="customer_db",
        data_classification=DataClassification.PII,
    )
    defaults.update(kwargs)
    return Action(**defaults)


def test_empty_session():
    engine = TrajectoryEngine()
    result = engine.analyze("nonexistent-session")
    assert not result.anomaly_detected
    assert result.action_count == 0


def test_single_safe_action():
    engine = TrajectoryEngine()
    a = _action(data_classification=DataClassification.PUBLIC)
    engine.record(a)
    result = engine.analyze("sess-1")
    assert not result.anomaly_detected


def test_pii_exfil_detected():
    engine = TrajectoryEngine()
    # Step 1: read PII
    engine.record(_action(operation="read", data_classification=DataClassification.PII))
    # Step 2: external transfer
    engine.record(
        _action(
            tool="http",
            operation="send",
            resource="payload",
            data_classification=DataClassification.PII,
            destination="https://evil.example.com",
        )
    )
    result = engine.analyze("sess-1")
    assert result.anomaly_detected
    assert result.pattern_name == "PII_EXFIL"


def test_data_stage_detected():
    engine = TrajectoryEngine()
    for _ in range(3):
        engine.record(_action(data_classification=DataClassification.SECRET))
    result = engine.analyze("sess-1")
    assert result.anomaly_detected
    assert result.pattern_name in ("PII_EXFIL", "DATA_STAGE")


def test_sessions_are_isolated():
    engine = TrajectoryEngine()
    engine.record(_action(session_id="sess-A", data_classification=DataClassification.PII))
    # sess-B has no external transfer → no anomaly
    engine.record(
        _action(
            session_id="sess-B",
            tool="http",
            operation="send",
            resource="x",
            data_classification=DataClassification.PUBLIC,
            destination="https://external.example.com",
        )
    )
    assert engine.analyze("sess-A").anomaly_detected is False
    assert engine.analyze("sess-B").anomaly_detected is False


def test_record_and_get_history():
    engine = TrajectoryEngine()
    a1 = _action()
    a2 = _action(operation="write")
    engine.record(a1)
    engine.record(a2)
    history = engine.get_history("sess-1")
    assert len(history) == 2
    assert history[0] == a1
