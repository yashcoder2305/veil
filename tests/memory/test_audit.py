"""tests/memory/test_audit.py"""

import json
import threading
from pathlib import Path

import pytest

from veil.memory.audit import AuditEngine, AuditRecord
from veil.models.action import Action, DataClassification
from veil.models.decisions import Decision, DecisionResult
from veil.models.results import PolicyResult, RiskLevel


def make_action(**kwargs) -> Action:
    defaults = dict(
        agent_id="SupportAgent",
        session_id="sess-001",
        tool="database",
        operation="read",
        resource="customer_db",
        data_classification=DataClassification.PII,
    )
    defaults.update(kwargs)
    return Action(**defaults)


def allow_decision() -> DecisionResult:
    return DecisionResult(
        decision=Decision.ALLOW,
        reason="All checks passed.",
        triggered_rules=[],
        confidence=1.0,
    )


def block_decision() -> DecisionResult:
    return DecisionResult(
        decision=Decision.BLOCK,
        reason="PII sent to external destination.",
        triggered_rules=["POLICY_PII_TO_EXTERNAL"],
        confidence=1.0,
    )


@pytest.fixture
def engine(tmp_path):
    return AuditEngine(audit_file=tmp_path / "audit.jsonl")


# --- Basic logging ---

def test_log_writes_record(engine, tmp_path):
    action = make_action()
    record = engine.log(action, allow_decision())
    assert isinstance(record, AuditRecord)
    assert record.decision == "ALLOW"
    assert record.agent_id == "SupportAgent"


def test_log_creates_file(engine, tmp_path):
    engine.log(make_action(), allow_decision())
    audit_file = tmp_path / "audit.jsonl"
    assert audit_file.exists()


def test_log_appends_json_lines(engine, tmp_path):
    engine.log(make_action(), allow_decision())
    engine.log(make_action(session_id="sess-002"), block_decision())
    lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        obj = json.loads(line)
        assert "action_id" in obj
        assert "decision" in obj


def test_log_includes_policy_result(engine):
    policy = PolicyResult(
        passed=False,
        violated_rules=["POLICY_PII_TO_EXTERNAL"],
        reason="Hard violation.",
    )
    record = engine.log(make_action(), block_decision(), policy_result=policy)
    assert record.policy_passed is False
    assert "POLICY_PII_TO_EXTERNAL" in record.policy_violated_rules


def test_log_includes_risk_level(engine):
    record = engine.log(make_action(), allow_decision(), risk_level=RiskLevel.HIGH)
    assert record.risk_level == "HIGH"


def test_log_includes_injection_flag(engine):
    record = engine.log(make_action(), allow_decision(), injection_detected=True)
    assert record.injection_detected is True


# --- Query ---

def test_query_returns_all_records(engine):
    engine.log(make_action(session_id="sess-A"), allow_decision())
    engine.log(make_action(session_id="sess-B"), block_decision())
    all_records = engine.query()
    assert len(all_records) == 2


def test_query_filters_by_session(engine):
    engine.log(make_action(session_id="sess-A"), allow_decision())
    engine.log(make_action(session_id="sess-B"), block_decision())
    records = engine.query(session_id="sess-A")
    assert len(records) == 1
    assert records[0].session_id == "sess-A"


def test_query_empty_file_returns_empty_list(engine):
    assert engine.query() == []


def test_query_nonexistent_file_returns_empty_list(tmp_path):
    engine = AuditEngine(audit_file=tmp_path / "nonexistent.jsonl")
    assert engine.query() == []


# --- Thread safety ---

def test_concurrent_writes_no_corruption(tmp_path):
    engine = AuditEngine(audit_file=tmp_path / "concurrent.jsonl")
    errors = []

    def write_records():
        try:
            for i in range(10):
                engine.log(make_action(session_id=f"sess-{i}"), allow_decision())
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=write_records) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"Thread errors: {errors}"
    records = engine.query()
    assert len(records) == 50  # 5 threads × 10 writes


# --- REVOKE decision ---

def test_revoke_decision_logged(engine):
    decision = DecisionResult(
        decision=Decision.REVOKE,
        reason="Multi-step exfiltration detected.",
        triggered_rules=["POLICY_PII_TO_EXTERNAL"],
        confidence=1.0,
        revoked_capability="http.request",
    )
    record = engine.log(make_action(), decision)
    assert record.decision == "REVOKE"
    assert record.revoked_capability == "http.request"
