"""
veil/agents/decision.py

DecisionEngine — combines all upstream signals into a final Decision enum.

This is DETERMINISTIC — no LLM calls. The LLM findings (CounterAgent,
JudgeAgent) are inputs but cannot override a hard deterministic BLOCK.

Decision priority (highest wins):
  1. Capability revoked                       → REVOKE
  2. Capability denied                        → BLOCK
  3. Hard policy violation (no escalation)    → BLOCK
  4. Injection detected (with high conf.)     → BLOCK
  5. Judge upheld concern                     → per judge recommendation
  6. Policy violation (with escalation)       → REQUIRE_APPROVAL
  7. Risk CRITICAL or HIGH                    → WARN (or REQUIRE_APPROVAL)
  8. Injection detected (low conf.)           → WARN
  9. Everything else                          → ALLOW
"""

from __future__ import annotations

from typing import Optional

from veil.models.decisions import Decision, DecisionResult
from veil.models.results import (
    CapabilityResult,
    InjectionResult,
    PolicyResult,
    RiskLevel,
    RiskResult,
)

# Judge verdict import — optional dependency to avoid circular imports
try:
    from veil.agents.judge import JudgeVerdict
except ImportError:
    JudgeVerdict = None  # type: ignore


# Map judge recommendation strings to Decision enum
_JUDGE_REC_MAP: dict[str, Decision] = {
    "ALLOW": Decision.ALLOW,
    "WARN": Decision.WARN,
    "REQUIRE_APPROVAL": Decision.REQUIRE_APPROVAL,
    "BLOCK": Decision.BLOCK,
    "REVOKE": Decision.REVOKE,
}


class DecisionEngine:
    """
    Combines capability, policy, risk, injection, and judge signals into
    a single DecisionResult.

    Usage:
        engine = DecisionEngine()
        result = engine.decide(risk_result, policy_result, capability_result,
                               injection_result, judge_verdict)
    """

    def decide(
        self,
        risk_result: RiskResult,
        policy_result: PolicyResult,
        capability_result: CapabilityResult,
        injection_result: Optional[InjectionResult] = None,
        judge_verdict=None,  # JudgeVerdict | None
    ) -> DecisionResult:
        """
        Return a DecisionResult based on all upstream signals.
        """
        triggered_rules: list[str] = []
        confidence = 1.0

        # ------------------------------------------------------------------
        # Priority 1: Capability revoked
        # ------------------------------------------------------------------
        if capability_result.is_revoked:
            return DecisionResult(
                decision=Decision.REVOKE,
                reason=f"Capability '{capability_result.requested_capability}' was previously revoked for this session.",
                triggered_rules=["capability.revoked"],
                confidence=1.0,
                requires_human_review=False,
                revoked_capability=capability_result.requested_capability,
            )

        # ------------------------------------------------------------------
        # Priority 2: Capability denied (not granted)
        # ------------------------------------------------------------------
        if not capability_result.allowed:
            return DecisionResult(
                decision=Decision.BLOCK,
                reason=f"Agent '{capability_result.agent_id}' does not hold capability '{capability_result.requested_capability}'. {capability_result.reason}",
                triggered_rules=["capability.denied"],
                confidence=1.0,
                requires_human_review=False,
            )

        # ------------------------------------------------------------------
        # Priority 3: Hard policy violation (no escalation path)
        # ------------------------------------------------------------------
        if not policy_result.passed and not policy_result.requires_escalation:
            triggered_rules.extend(policy_result.violated_rules)
            return DecisionResult(
                decision=Decision.BLOCK,
                reason=f"Hard policy violation: {policy_result.reason}",
                triggered_rules=triggered_rules,
                confidence=1.0,
                requires_human_review=False,
            )

        # ------------------------------------------------------------------
        # Priority 4: High-confidence injection detected
        # ------------------------------------------------------------------
        if injection_result and injection_result.detected and injection_result.confidence >= 0.75:
            triggered_rules.append("injection.detected")
            triggered_rules.extend(
                f"injection.signal:{s}" for s in injection_result.signals
            )
            return DecisionResult(
                decision=Decision.BLOCK,
                reason=f"High-confidence injection detected in '{injection_result.source_field}': {', '.join(injection_result.signals[:3])}",
                triggered_rules=triggered_rules,
                confidence=injection_result.confidence,
                requires_human_review=True,
            )

        # ------------------------------------------------------------------
        # Priority 5: Judge upheld the concern
        # ------------------------------------------------------------------
        if judge_verdict is not None and judge_verdict.upheld:
            rec = _JUDGE_REC_MAP.get(
                judge_verdict.recommended_decision.upper(), Decision.BLOCK
            )
            triggered_rules.append("judge.concern_upheld")
            confidence = judge_verdict.confidence
            return DecisionResult(
                decision=rec,
                reason=f"Judge upheld security concern: {judge_verdict.reasoning}",
                triggered_rules=triggered_rules,
                confidence=round(confidence, 3),
                requires_human_review=(rec == Decision.REQUIRE_APPROVAL or confidence < 0.6),
            )

        # ------------------------------------------------------------------
        # Priority 6: Policy violation requiring escalation
        # ------------------------------------------------------------------
        if not policy_result.passed and policy_result.requires_escalation:
            triggered_rules.extend(policy_result.violated_rules)
            return DecisionResult(
                decision=Decision.REQUIRE_APPROVAL,
                reason=f"Policy requires escalation: {policy_result.reason}",
                triggered_rules=triggered_rules,
                confidence=1.0,
                requires_human_review=True,
            )

        # ------------------------------------------------------------------
        # Priority 7: Risk CRITICAL or HIGH
        # ------------------------------------------------------------------
        if risk_result.level == RiskLevel.CRITICAL:
            triggered_rules.extend(risk_result.contributing_factors)
            return DecisionResult(
                decision=Decision.REQUIRE_APPROVAL,
                reason=f"Critical risk score ({risk_result.score:.2f}): {', '.join(risk_result.contributing_factors[:3])}",
                triggered_rules=triggered_rules,
                confidence=1.0,
                requires_human_review=True,
            )
        if risk_result.level == RiskLevel.HIGH:
            triggered_rules.extend(risk_result.contributing_factors)
            return DecisionResult(
                decision=Decision.WARN,
                reason=f"High risk score ({risk_result.score:.2f}): {', '.join(risk_result.contributing_factors[:3])}",
                triggered_rules=triggered_rules,
                confidence=1.0,
                requires_human_review=False,
            )

        # ------------------------------------------------------------------
        # Priority 8: Low-confidence injection signal
        # ------------------------------------------------------------------
        if injection_result and injection_result.detected:
            triggered_rules.append("injection.low_confidence")
            return DecisionResult(
                decision=Decision.WARN,
                reason=f"Low-confidence injection signal in '{injection_result.source_field}'.",
                triggered_rules=triggered_rules,
                confidence=injection_result.confidence,
                requires_human_review=False,
            )

        # ------------------------------------------------------------------
        # Priority 9: ALLOW — nothing fired
        # ------------------------------------------------------------------
        return DecisionResult(
            decision=Decision.ALLOW,
            reason="All checks passed; action is permitted.",
            triggered_rules=[],
            confidence=1.0,
            requires_human_review=False,
        )
