"""
tests/intelligence/test_decision.py
"""
from __future__ import annotations

import pytest
from veil.models.decisions import Decision
from veil.models.results import (
    CapabilityResult,
    InjectionResult,
    PolicyResult,
    RiskLevel,
    RiskResult,
)
from veil.agents.decision import DecisionEngine


def _cap(allowed: bool = True, revoked: bool = False) -> CapabilityResult:
    return CapabilityResult(
        allowed=allowed,
        agent_id="agent-1",
        requested_capability="database.read",
        reason="test",
        is_revoked=revoked,
    )


def _policy(passed: bool = True, escalate: bool = False, rules: list = None) -> PolicyResult:
    return PolicyResult(
        passed=passed,
        violated_rules=rules or ([] if passed else ["RULE_1"]),
        reason="ok" if passed else "violated",
        requires_escalation=escalate,
    )


def _risk(level: RiskLevel = RiskLevel.NONE, score: float = 0.0) -> RiskResult:
    return RiskResult(
        level=level,
        score=score,
        contributing_factors=[],
        trajectory_anomaly=False,
    )


def _injection(detected: bool = False, confidence: float = 0.0) -> InjectionResult:
    return InjectionResult(
        detected=detected,
        signals=["ignore_previous_instructions in purpose"] if detected else [],
        confidence=confidence,
        source_field="purpose" if detected else None,
    )


engine = DecisionEngine()


def test_all_clear_allows():
    result = engine.decide(_risk(), _policy(), _cap())
    assert result.decision == Decision.ALLOW


def test_revoked_capability():
    result = engine.decide(_risk(), _policy(), _cap(revoked=True))
    assert result.decision == Decision.REVOKE
    assert result.revoked_capability == "database.read"


def test_denied_capability_blocks():
    result = engine.decide(_risk(), _policy(), _cap(allowed=False))
    assert result.decision == Decision.BLOCK
    assert "capability.denied" in result.triggered_rules


def test_hard_policy_violation_blocks():
    result = engine.decide(_risk(), _policy(passed=False, escalate=False), _cap())
    assert result.decision == Decision.BLOCK


def test_policy_escalation_requires_approval():
    result = engine.decide(_risk(), _policy(passed=False, escalate=True), _cap())
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.requires_human_review


def test_high_confidence_injection_blocks():
    result = engine.decide(
        _risk(),
        _policy(),
        _cap(),
        injection_result=_injection(detected=True, confidence=0.99),
    )
    assert result.decision == Decision.BLOCK
    assert result.requires_human_review


def test_low_confidence_injection_warns():
    result = engine.decide(
        _risk(),
        _policy(),
        _cap(),
        injection_result=_injection(detected=True, confidence=0.25),
    )
    assert result.decision == Decision.WARN


def test_critical_risk_requires_approval():
    result = engine.decide(_risk(RiskLevel.CRITICAL, 0.95), _policy(), _cap())
    assert result.decision == Decision.REQUIRE_APPROVAL


def test_high_risk_warns():
    result = engine.decide(_risk(RiskLevel.HIGH, 0.75), _policy(), _cap())
    assert result.decision == Decision.WARN


def test_revoke_takes_priority_over_injection():
    """Revoked capability wins over any injection signal."""
    result = engine.decide(
        _risk(),
        _policy(),
        _cap(revoked=True),
        injection_result=_injection(detected=True, confidence=0.99),
    )
    assert result.decision == Decision.REVOKE
