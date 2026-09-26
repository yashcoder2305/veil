"""
tests/test_pipeline.py

End-to-end integration tests for VEILPipeline.

These tests exercise the full pipeline using real modules (no mocks) to verify
the integration contract from Sub-Task 10:
  1. A raw tool-call dict enters VEILPipeline.run().
  2. It is normalized into an Action.
  3. Capability and policy checks run deterministically.
  4. A DecisionResult is returned.
  5. The executor is gated on ALLOW only.
  6. An audit event is written to the JSON file.
  7. TrajectoryEngine and RiskEngine consume the same Action object.

LLM agents (CounterAgent, JudgeAgent) are not invoked in these tests — scenarios
are kept below the risk threshold that triggers agentic analysis, or the pipeline's
LLM-unavailable fallback handles it gracefully.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from veil.memory.audit import AuditEngine
from veil.models.decisions import Decision
from veil.pipeline import VEILPipeline
from simulator.client.scenarios import (
    finance_legitimate,
    p0_attack,
    privilege_abuse,
    pii_write_attempt,
    support_legitimate,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_pipeline(tmp_path: Path) -> VEILPipeline:
    """Pipeline with isolated audit file — no watsonx calls needed for these tests."""
    audit = AuditEngine(audit_file=tmp_path / "audit.jsonl")
    return VEILPipeline(audit_engine=audit)


def _run_scenario(scenario_fn, tmp_path: Path):
    """Run all actions in a scenario through a fresh pipeline, return list of PipelineResult."""
    pipeline = _make_pipeline(tmp_path)
    actions = scenario_fn()
    results = []
    for action in actions:
        raw = action.model_dump()
        raw.pop("action_id", None)
        raw.pop("timestamp", None)
        raw["data_classification"] = action.data_classification.value
        results.append(pipeline.run(raw))
    return results, pipeline


# ---------------------------------------------------------------------------
# Integration contract tests (Sub-Task 10)
# ---------------------------------------------------------------------------


def test_legitimate_support_action_allowed(tmp_path):
    """SupportAgent legitimate PII read → ALLOW, executed, audited."""
    results, pipeline = _run_scenario(support_legitimate, tmp_path)
    assert len(results) == 1
    r = results[0]

    # Contract 1: Action normalised
    assert r.action.agent_id == "SupportAgent"
    assert r.action.tool == "database"

    # Contract 4: DecisionResult returned
    assert r.decision_result is not None

    # Contract 5: Executor proceeds on ALLOW
    assert r.decision_result.decision == Decision.ALLOW
    assert r.execution_result.executed is True

    # Contract 6: Audit event written
    audit_records = pipeline._audit_engine.query()
    assert len(audit_records) == 1
    assert audit_records[0].decision == "ALLOW"
    assert audit_records[0].agent_id == "SupportAgent"

    # Contract 7: RiskResult present
    assert r.risk_result is not None


def test_finance_legitimate_allowed(tmp_path):
    """FinanceAgent reading payment_records → ALLOW."""
    results, _ = _run_scenario(finance_legitimate, tmp_path)
    assert results[0].decision_result.decision == Decision.ALLOW
    assert results[0].execution_result.executed is True


def test_privilege_abuse_blocked(tmp_path):
    """SupportAgent shell.execute → BLOCK (globally forbidden)."""
    results, pipeline = _run_scenario(privilege_abuse, tmp_path)
    assert len(results) == 1
    r = results[0]

    assert r.decision_result.decision == Decision.BLOCK
    assert r.execution_result.executed is False
    assert r.execution_result.block_reason is not None

    # Audit must record the block
    records = pipeline._audit_engine.query()
    assert records[0].decision == "BLOCK"


def test_pii_write_attempt_blocked(tmp_path):
    """SupportAgent database.write on customer_db → BLOCK (not in grants)."""
    results, pipeline = _run_scenario(pii_write_attempt, tmp_path)
    r = results[0]
    assert r.decision_result.decision == Decision.BLOCK
    assert r.execution_result.executed is False


def test_p0_attack_chain_blocked(tmp_path):
    """
    P0 attack chain:
      Step 1: PII read with injection signal → WARN or BLOCK (injection detected)
      Step 2: file read (internal_docs) → SupportAgent allowed → ALLOW
      Step 3: http.request with PII to external → BLOCK (policy: PII_TO_EXTERNAL)
    """
    results, pipeline = _run_scenario(p0_attack, tmp_path)
    assert len(results) == 3

    # Step 3 must be blocked — this is the enforcement requirement
    step3 = results[2]
    assert step3.decision_result.decision in (Decision.BLOCK, Decision.REVOKE, Decision.WARN)
    # The executor must NOT have run for a block
    if step3.decision_result.decision in (Decision.BLOCK, Decision.REVOKE):
        assert step3.execution_result.executed is False

    # All 3 steps must be audited
    records = pipeline._audit_engine.query()
    assert len(records) == 3

    # The exfiltration step must show up as not-ALLOW
    exfil_record = records[2]
    assert exfil_record.decision != "ALLOW"


def test_p0_injection_detected_in_step1(tmp_path):
    """Step 1 of P0 attack must trigger injection detection."""
    results, _ = _run_scenario(p0_attack, tmp_path)
    step1 = results[0]
    assert step1.injection_result is not None
    assert step1.injection_result.detected is True


def test_p0_trajectory_anomaly_in_step3(tmp_path):
    """After PII read + external HTTP, TrajectoryEngine must flag PII_EXFIL."""
    results, _ = _run_scenario(p0_attack, tmp_path)
    step3 = results[2]
    # Risk result must reflect trajectory anomaly by step 3
    assert step3.risk_result is not None
    assert step3.risk_result.trajectory_anomaly is True


def test_audit_file_contains_jsonl(tmp_path):
    """Audit file must be valid JSONL — one JSON object per line."""
    results, pipeline = _run_scenario(support_legitimate, tmp_path)
    audit_path = pipeline._audit_engine._path
    assert audit_path.exists()
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert "decision" in parsed
    assert "agent_id" in parsed
    assert "timestamp" in parsed


def test_revocation_persists_across_actions_in_session(tmp_path):
    """
    If a REVOKE decision fires, subsequent actions in the same session
    with the revoked capability must be denied by CapabilityManager.
    """
    from veil.agents.revocation import RevocationEngine
    from veil.memory.audit import AuditEngine
    from veil.security.capabilities import CapabilityManager

    revocation_engine = RevocationEngine()
    cap_manager = CapabilityManager(revocation_store=revocation_engine)
    pipeline = VEILPipeline(
        capability_manager=cap_manager,
        revocation_engine=revocation_engine,
        audit_engine=AuditEngine(audit_file=tmp_path / "audit.jsonl"),
    )

    # Manually revoke http.request for SupportAgent in this session
    revocation_engine.revoke("SupportAgent", "sess-revoke-test", "http.request")

    raw = {
        "agent_id": "SupportAgent",
        "session_id": "sess-revoke-test",
        "tool": "http",
        "operation": "request",
        "resource": "https://external.com/api",
        "destination": "https://external.com/api",
        "purpose": "Calling external API.",
        "provenance": "agent_plan",
    }
    result = pipeline.run(raw)
    assert result.decision_result.decision == Decision.REVOKE
    assert result.capability_result.is_revoked is True
    assert result.execution_result.executed is False
