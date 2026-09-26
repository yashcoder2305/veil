"""
tests/intelligence/test_risk.py
"""
from __future__ import annotations

import pytest
from veil.models.action import Action, DataClassification
from veil.models.results import CapabilityResult, PolicyResult, RiskLevel
from veil.security.risk import RiskEngine
from veil.security.trajectory import TrajectoryAnalysis


def _cap(allowed: bool = True, revoked: bool = False) -> CapabilityResult:
    return CapabilityResult(
        allowed=allowed,
        agent_id="agent-1",
        requested_capability="database.read",
        reason="test",
        is_revoked=revoked,
    )


def _policy(passed: bool = True, escalate: bool = False) -> PolicyResult:
    return PolicyResult(
        passed=passed,
        violated_rules=[] if passed else ["POLICY_TEST"],
        reason="ok" if passed else "violated",
        requires_escalation=escalate,
    )


def _traj(anomaly: bool = False) -> TrajectoryAnalysis:
    return TrajectoryAnalysis(
        session_id="sess-1",
        anomaly_detected=anomaly,
        pattern_name="PII_EXFIL" if anomaly else "",
        description="test",
        action_count=1,
    )


def _action(**kwargs) -> Action:
    defaults = dict(
        agent_id="agent-1",
        session_id="sess-1",
        tool="database",
        operation="read",
        resource="customer_db",
        data_classification=DataClassification.PUBLIC,
    )
    defaults.update(kwargs)
    return Action(**defaults)


engine = RiskEngine()


def test_low_risk_allowed_public():
    result = engine.score(
        _action(),
        _cap(allowed=True),
        _policy(passed=True),
        _traj(anomaly=False),
    )
    assert result.level in (RiskLevel.NONE, RiskLevel.LOW)
    assert result.score < 0.4


def test_capability_denied_raises_risk():
    result = engine.score(
        _action(),
        _cap(allowed=False),
        _policy(passed=True),
        _traj(),
    )
    # capability_denied contributes 0.25 * 0.8 = 0.2 → LOW/MEDIUM
    assert result.level in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert result.score >= 0.2
    assert "capability_denied" in result.contributing_factors


def test_pii_external_critical():
    result = engine.score(
        _action(
            data_classification=DataClassification.PII,
            destination="https://external.example.com",
            operation="send",
            tool="http",
        ),
        _cap(allowed=True),
        _policy(passed=False, escalate=False),
        _traj(anomaly=True),
    )
    # PII(0.25*0.8) + ext_dest(0.20*0.9) + policy(0.20*0.7) + traj(0.10*1.0) = 0.62 → HIGH
    assert result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert result.trajectory_anomaly is True
    assert "external_destination" in result.contributing_factors


def test_trajectory_anomaly_included():
    result = engine.score(
        _action(),
        _cap(),
        _policy(),
        _traj(anomaly=True),
    )
    assert result.trajectory_anomaly is True
    assert any("trajectory" in f for f in result.contributing_factors)
